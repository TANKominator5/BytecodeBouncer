//go:build linux

package dataplane

// These fixtures exercise the real compiled XDP program with BPF_PROG_TEST_RUN;
// no host interface is attached or modified. Set TC_BPF_TEST=1 as root to run.
import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TANKominator5/BytecodeBouncer/internal/contract"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	drop       = contract.Drop
	pass       = contract.Pass
	bounce     = contract.Bounce
	honeypot   = contract.Honeypot
	limit      = contract.Limit
	jailAction = contract.Jail
)

type testAddress = contract.Address
type testPrefix = contract.Prefix
type testRuleCounters = contract.RuleCounters
type testRule = contract.Rule
type testConfig = contract.Config
type testSetKey = contract.SetKey
type testHealth = contract.Health
type testJail = contract.JailValue
type testBucket = contract.BucketValue
type testScan = contract.ScanValue
type testEvent = contract.EventRecord

func TestPolicyABI(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name       string
		kind       ebpf.MapType
		entries    uint32
		key, value any
	}{
		{"config", ebpf.Array, 1, uint32(0), testConfig{}},
		{"rule_counters", ebpf.PerCPUArray, 64, uint32(0), testRuleCounters{}},
		{"health", ebpf.PerCPUArray, 1, uint32(0), testHealth{}},
		{"sources", ebpf.Hash, 1048576, testAddress{}, uint64(0)},
		{"jail", ebpf.Hash, 1048576, testAddress{}, testJail{}},
		{"scans", ebpf.Hash, 65536, testAddress{}, testScan{}},
		{"sets", ebpf.LPMTrie, 10000, testSetKey{}, uint32(0)},
	}
	for _, c := range cases {
		m := spec.Maps[c.name]
		if m == nil || m.Type != c.kind || m.MaxEntries != c.entries || m.KeySize != uint32(binary.Size(c.key)) || m.ValueSize != uint32(binary.Size(c.value)) {
			t.Fatalf("%s ABI mismatch: %+v", c.name, m)
		}
	}
	m := spec.Maps["buckets"]
	if m.Type != ebpf.ArrayOfMaps || m.MaxEntries != 64 || m.InnerMap == nil || m.InnerMap.Type != ebpf.LRUHash || m.InnerMap.MaxEntries != 65536 || m.InnerMap.KeySize != 24 || m.InnerMap.ValueSize != uint32(binary.Size(testBucket{})) {
		t.Fatalf("bucket ABI: %+v", m)
	}
	if spec.Maps["events"].Type != ebpf.RingBuf || spec.Maps["events"].MaxEntries != 1<<24 {
		t.Fatal("event ring ABI")
	}
	// Check member offsets as well as aggregate sizes (padding bugs can preserve size).
	var rule *btf.Struct
	if err := spec.Types.TypeByName("tc_rule", &rule); err != nil {
		t.Fatal(err)
	}
	for name, offset := range map[string]btf.Bits{"line": 0, "matches": 32, "action": 64, "src": 192, "dst": 352, "sport_min": 512, "family": 592, "log": 632} {
		found := false
		for _, member := range rule.Members {
			if member.Name == name {
				found = true
				if member.Offset != offset {
					t.Fatalf("rule.%s offset %d != %d", name, member.Offset, offset)
				}
			}
		}
		if !found {
			t.Fatalf("missing rule.%s", name)
		}
	}
	var event *btf.Struct
	if err := spec.Types.TypeByName("tc_event", &event); err != nil {
		t.Fatal(err)
	}
	if event.Size != uint32(binary.Size(testEvent{})) {
		t.Fatal("event size")
	}
}

func addr(s string) testAddress {
	ip := netip.MustParseAddr(s)
	result := testAddress{Family: 6, Bytes: ip.As16()}
	if ip.Is4() {
		result = testAddress{Family: 4}
		v := ip.As4()
		copy(result.Bytes[:], v[:])
	}
	return result
}
func prefix(s string) testPrefix {
	p := netip.MustParsePrefix(s).Masked()
	a := addr(p.Addr().String())
	return testPrefix{Bytes: a.Bytes, Family: a.Family, Bits: uint8(p.Bits())}
}
func cfg(rules ...testRule) testConfig {
	c := testConfig{Generation: 1, DefaultAction: pass, FragmentAction: drop, RuleCount: uint32(len(rules))}
	copy(c.Rules[:], rules)
	return c
}
func requireBPF(t *testing.T) {
	t.Helper()
	if os.Getenv("TC_BPF_TEST") != "1" {
		t.Skip("set TC_BPF_TEST=1 as root for kernel tests")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
}
func loadPolicy(t *testing.T, config testConfig, shared map[string]*ebpf.Map) *ebpf.Collection {
	return loadPolicySized(t, config, shared, 0)
}

// Small capacities exercise saturation without allocating hundreds of MiB.
func loadPolicySized(t *testing.T, config testConfig, shared map[string]*ebpf.Map, capacity uint32) *ebpf.Collection {
	t.Helper()
	requireBPF(t)
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		t.Fatal(err)
	}
	if err := reserveBucketCapacity(spec); err != nil {
		t.Fatal(err)
	}
	if capacity != 0 {
		spec.Maps["scans"].MaxEntries = capacity
		spec.Maps["jail"].MaxEntries = capacity
	}
	spec.Maps["config"].Contents = []ebpf.MapKV{{Key: uint32(0), Value: config}}
	c, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: shared, Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats}})
	if err != nil {
		// Branch-level logs are expensive on success; retry only a failed load
		// to preserve the exact verifier rejection and register state.
		diagnostic, detailedErr := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: shared, Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelBranch | ebpf.LogLevelStats}})
		if diagnostic != nil {
			diagnostic.Close()
		}
		var verifier *ebpf.VerifierError
		if errors.As(detailedErr, &verifier) {
			t.Fatalf("verifier: %+v", verifier)
		}
		t.Fatalf("load XDP (verifier): %+v", err)
	}
	t.Cleanup(c.Close)
	if err := c.Maps["config"].Freeze(); err != nil {
		t.Fatal(err)
	}
	var bucketKeys, bucketFDs []uint32
	for i := uint32(0); i < config.RuleCount; i++ {
		if config.Rules[i].Action != limit {
			continue
		}
		m := c.Maps["bucket_template"]
		if len(bucketKeys) != 0 {
			m, err = ebpf.NewMap(spec.Maps["buckets"].InnerMap)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { m.Close() })
		}
		bucketKeys = append(bucketKeys, i)
		bucketFDs = append(bucketFDs, uint32(m.FD()))
	}
	// Populate a PRIVATE outer map in one syscall, avoiding one RCU wait for
	// each slot. Never use this to mutate an attached generation's map layout.
	if len(bucketKeys) > 0 {
		if _, err := c.Maps["buckets"].BatchUpdate(bucketKeys, bucketFDs, nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, line := range strings.Split(c.Programs["trafficcop"].VerifierLog, "\n") {
		if strings.HasPrefix(line, "processed ") || strings.HasPrefix(line, "verification time ") {
			t.Log(line)
		}
	}
	return c
}
func runPacket(t *testing.T, c *ebpf.Collection, frame []byte, want uint32) []byte {
	t.Helper()
	verdict, output, err := c.Programs["trafficcop"].Test(frame)
	if err != nil {
		t.Fatal(err)
	}
	if verdict != want {
		t.Fatalf("verdict %d != %d (frame %x)", verdict, want, frame)
	}
	return output
}
func totals(t *testing.T, c *ebpf.Collection) Counters {
	t.Helper()
	var perCPU []Counters
	if err := c.Maps["counters"].Lookup(uint32(0), &perCPU); err != nil {
		t.Fatal(err)
	}
	var sum Counters
	for _, v := range perCPU {
		sum.Passed += v.Passed
		sum.Dropped += v.Dropped
		sum.Bounced += v.Bounced
		sum.Honeypotted += v.Honeypotted
		sum.Malformed += v.Malformed
		sum.Other += v.Other
		sum.Jailed += v.Jailed
		sum.DefaultHits += v.DefaultHits
	}
	return sum
}
func ruleTotals(t *testing.T, c *ebpf.Collection, index uint32) testRuleCounters {
	t.Helper()
	var values []testRuleCounters
	if err := c.Maps["rule_counters"].Lookup(index, &values); err != nil {
		t.Fatal(err)
	}
	var result testRuleCounters
	for _, v := range values {
		result.Hits += v.Hits
		result.Passed += v.Passed
		result.Dropped += v.Dropped
		result.Bounced += v.Bounced
		result.Honeypotted += v.Honeypotted
	}
	return result
}
func healthy(t *testing.T, c *ebpf.Collection) {
	t.Helper()
	var values []testHealth
	if err := c.Maps["health"].Lookup(uint32(0), &values); err != nil {
		t.Fatal(err)
	}
	for _, v := range values {
		if v != (testHealth{}) {
			t.Fatalf("dataplane health failure: %+v", v)
		}
	}
}
func ethernet(ether uint16, payload []byte) []byte {
	f := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0}
	binary.BigEndian.PutUint16(f[12:], ether)
	return append(f, payload...)
}
func ipv4(src string, proto byte, fragment uint16, ihl byte, payload []byte) []byte {
	p := make([]byte, int(ihl)*4)
	if len(p) < 20 {
		p = make([]byte, 20)
	}
	p[0] = 0x40 | ihl
	p[9] = proto
	binary.BigEndian.PutUint16(p[6:], fragment)
	a := addr(src)
	copy(p[12:16], a.Bytes[:4])
	copy(p[16:], []byte{10, 0, 0, 1})
	return ethernet(0x0800, append(p, payload...))
}
func ipv6(src string, proto byte, payload []byte) []byte {
	p := make([]byte, 40)
	p[0] = 0x60
	p[6] = proto
	a := addr(src)
	copy(p[8:], a.Bytes[:])
	d := addr("2001:db8::1")
	copy(p[24:], d.Bytes[:])
	return ethernet(0x86dd, append(p, payload...))
}
func udp(port uint16) []byte {
	p := make([]byte, 8)
	binary.BigEndian.PutUint16(p, 40000)
	binary.BigEndian.PutUint16(p[2:], port)
	return p
}
func tcp(port uint16) []byte { return append(udp(port), make([]byte, 12)...) }
func vlan(f []byte, id uint16, ether uint16) []byte {
	p := []byte{0x81, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(p[2:], id)
	binary.BigEndian.PutUint16(p[4:], ether)
	return append(append(append([]byte{}, f[:12]...), p...), f[14:]...)
}
func chain(n int, last byte, payload []byte) []byte {
	p := make([]byte, n*8)
	for i := 0; i < n; i++ {
		p[i*8] = 60
	}
	if n > 0 {
		p[(n-1)*8] = last
	}
	return append(p, payload...)
}

func TestKernelParsing(t *testing.T) {
	c := loadPolicy(t, cfg(), nil)
	// Sub-14-byte frames cannot be submitted by the kernel test-run API; native
	// parser fixtures below cover those exact lengths without Ethernet padding.
	cases := []struct {
		name                       string
		frame                      []byte
		verdict                    uint32
		other, malformed, defaults uint64
	}{
		{"arp", ethernet(0x0806, make([]byte, 46)), pass, 1, 0, 0},
		{"short-vlan", ethernet(0x8100, nil), pass, 1, 0, 0},
		{"double-vlan", vlan(ethernet(0x8100, nil), 1, 0x8100), pass, 1, 0, 0},
		{"double-provider", vlan(ethernet(0x88a8, nil), 1, 0x88a8), pass, 1, 0, 0},
		{"provider-outer", ethernet(0x88a8, make([]byte, 46)), pass, 1, 0, 0},
		{"short-ipv4", ethernet(0x0800, make([]byte, 19)), drop, 0, 1, 0},
		{"bad-ihl", ipv4("10.1.2.3", 17, 0, 4, udp(53)), drop, 0, 1, 0},
		{"short-options", ipv4("10.1.2.3", 17, 0, 15, nil)[:54], drop, 0, 1, 0},
		{"options", ipv4("10.1.2.3", 17, 0, 15, udp(53)), pass, 0, 0, 1},
		{"vlan-options", vlan(ipv4("10.1.2.3", 17, 0, 15, udp(53)), 4095, 0x0800), pass, 0, 0, 1},
		{"short-udp", ipv4("10.1.2.3", 17, 0, 5, make([]byte, 7)), drop, 0, 1, 0},
		{"short-tcp", ipv4("10.1.2.3", 6, 0, 5, make([]byte, 19)), drop, 0, 1, 0},
		{"short-icmp", ipv4("10.1.2.3", 1, 0, 5, make([]byte, 7)), drop, 0, 1, 0},
		{"first-fragment", ipv4("10.1.2.3", 17, 0x2000, 5, udp(53)), pass, 0, 0, 1},
		{"nonfirst-no-transport", ipv4("10.1.2.3", 17, 1, 5, nil), drop, 0, 0, 0},
		{"unknown-protocol", ipv4("10.1.2.3", 99, 0, 5, nil), pass, 0, 0, 1},
		{"short-ipv6", ethernet(0x86dd, make([]byte, 39)), drop, 0, 1, 0},
		{"ipv6-udp", ipv6("2001:db8::2", 17, udp(53)), pass, 0, 0, 1},
		{"variable-extension", ipv6("2001:db8::2", 43, append(append([]byte{17, 31}, make([]byte, 254)...), udp(53)...)), pass, 0, 0, 1},
		{"eight-extensions", ipv6("2001:db8::2", 0, chain(8, 17, udp(53))), pass, 0, 0, 1},
		{"nine-extensions", ipv6("2001:db8::2", 0, chain(9, 17, udp(53))), drop, 0, 1, 0},
		{"short-extension", ipv6("2001:db8::2", 43, make([]byte, 7)), drop, 0, 1, 0},
		{"extension-length", ipv6("2001:db8::2", 60, []byte{17, 255, 0, 0, 0, 0, 0, 0}), drop, 0, 1, 0},
		{"short-icmp6", ipv6("2001:db8::2", 58, make([]byte, 7)), drop, 0, 1, 0},
		{"v6-first-fragment", ipv6("2001:db8::2", 44, append([]byte{17, 0, 0, 1, 0, 0, 0, 0}, udp(53)...)), pass, 0, 0, 1},
		{"v6-nonfirst", ipv6("2001:db8::2", 44, []byte{17, 0, 0, 8, 0, 0, 0, 0}), drop, 0, 0, 0},
		{"v6-nonfirst-extension", ipv6("2001:db8::2", 44, append([]byte{60, 0, 0, 8, 0, 0, 0, 0}, chain(1, 17, nil)...)), drop, 0, 0, 0},
		{"v6-nonfirst-short-extension", ipv6("2001:db8::2", 44, []byte{60, 0, 0, 8, 0, 0, 0, 0}), drop, 0, 1, 0},
		{"v6-nonfirst-nine-extensions", ipv6("2001:db8::2", 44, append([]byte{60, 0, 0, 8, 0, 0, 0, 0}, chain(8, 17, nil)...)), drop, 0, 1, 0},
	}
	bad4 := ipv4("10.1.2.3", 17, 0, 5, udp(53))
	bad4[14] = 0x65
	bad6 := ipv6("2001:db8::2", 17, udp(53))
	bad6[14] = 0x40
	mixed := make([]byte, 56)
	mixed[0] = 0
	mixed[1] = 1
	mixed[16] = 60
	mixed[24] = 44
	mixed[25] = 2
	mixed[48] = 17
	mixed[51] = 1
	cases = append(cases, struct {
		name                       string
		frame                      []byte
		verdict                    uint32
		other, malformed, defaults uint64
	}{"mixed-extension-chain", ipv6("2001:db8::2", 43, append(mixed, udp(53)...)), pass, 0, 0, 1})
	cases = append(cases, struct {
		name                       string
		frame                      []byte
		verdict                    uint32
		other, malformed, defaults uint64
	}{"bad-v4-version", bad4, drop, 0, 1, 0}, struct {
		name                       string
		frame                      []byte
		verdict                    uint32
		other, malformed, defaults uint64
	}{"bad-v6-version", bad6, drop, 0, 1, 0})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := totals(t, c)
			out := runPacket(t, c, tc.frame, tc.verdict)
			after := totals(t, c)
			if !bytes.Equal(out, tc.frame) {
				t.Fatal("parser modified frame")
			}
			if after.Other-before.Other != tc.other || after.Malformed-before.Malformed != tc.malformed || after.DefaultHits-before.DefaultHits != tc.defaults {
				t.Fatalf("classification: before %+v after %+v", before, after)
			}
		})
	}
	healthy(t, c)
}

func TestKernelRulesAndSets(t *testing.T) {
	r := testRule{Line: 37, Action: drop, Proto: 17, Family: 4, Matches: 1 | 2 | 16 | 32 | 128, Src: prefix("10.0.0.0/24"), Dst: prefix("10.0.0.1/32"), SportMin: 40000, SportMax: 40000, DportMin: 6000, DportMax: 6099, VLAN: 100, Log: 1}
	c := loadPolicy(t, cfg(r, testRule{Line: 99, Action: pass}), nil)
	reader, err := ringbuf.NewReader(c.Maps["events"])
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	for _, p := range []uint16{5999, 6000, 6099, 6100} {
		want := uint32(pass)
		if p >= 6000 && p <= 6099 {
			want = drop
		}
		runPacket(t, c, vlan(ipv4("10.0.0.255", 17, 0, 15, udp(p)), 100, 0x0800), want)
	}
	runPacket(t, c, vlan(ipv4("10.0.1.0", 17, 0, 5, udp(6000)), 100, 0x0800), pass)
	runPacket(t, c, ipv4("10.0.0.2", 17, 0, 5, udp(6000)), pass)
	runPacket(t, c, vlan(ipv4("10.0.0.2", 17, 1, 5, nil), 100, 0x0800), pass)
	for i := 0; i < 2; i++ {
		reader.SetDeadline(time.Now().Add(time.Second))
		rec, err := reader.Read()
		if err != nil {
			t.Fatal(err)
		}
		var event testEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &event); err != nil {
			t.Fatal(err)
		}
		if event.Line != 37 || event.Verdict != drop || event.HasPorts != 1 || event.Generation != 1 {
			t.Fatalf("event %+v", event)
		}
	}
	if got := ruleTotals(t, c, 0); got.Hits != 2 || got.Dropped != 2 {
		t.Fatalf("rule totals %+v", got)
	}
	healthy(t, c)

	t.Run("IPv6-partial-prefix", func(t *testing.T) {
		c := loadPolicy(t, cfg(testRule{Action: drop, Matches: 1, Src: prefix("2001:db8::/65")}), nil)
		for _, s := range []string{"2001:db8::", "2001:db8::ffff", "2001:db8:0:0:7fff:ffff:ffff:ffff"} {
			runPacket(t, c, ipv6(s, 17, udp(1)), drop)
		}
		runPacket(t, c, ipv6("2001:db8:0:0:8000::", 17, udp(1)), pass)
		runPacket(t, c, ipv4("0.0.0.1", 17, 0, 5, udp(1)), pass)
	})
	t.Run("sets-live-family-and-overlap", func(t *testing.T) {
		c := loadPolicy(t, cfg(testRule{Action: drop, Matches: 4, SrcSet: 3}), nil)
		for _, s := range []string{"10.0.0.0/24", "10.0.0.128/25", "2001:db8::/32"} {
			p := prefix(s)
			key := testSetKey{PrefixLen: 32 + uint32(p.Bits), Set: 3, Family: p.Family, Bytes: p.Bytes}
			if err := c.Maps["sets"].Put(key, uint32(1)); err != nil {
				t.Fatal(err)
			}
		}
		runPacket(t, c, ipv4("10.0.0.255", 17, 0, 5, udp(1)), drop)
		runPacket(t, c, ipv4("10.0.1.0", 17, 0, 5, udp(1)), pass)
		runPacket(t, c, ipv6("2001:db8:ffff::", 17, udp(1)), drop)
		p := prefix("0.0.0.0/0")
		key := testSetKey{PrefixLen: 32, Set: 3, Family: 4, Bytes: p.Bytes}
		if err := c.Maps["sets"].Put(key, uint32(1)); err != nil {
			t.Fatal(err)
		}
		runPacket(t, c, ipv4("255.255.255.255", 17, 0, 5, udp(1)), drop)
		runPacket(t, c, ipv6("2002::1", 17, udp(1)), pass)
		if err := c.Maps["sets"].Delete(key); err != nil {
			t.Fatal(err)
		}
		runPacket(t, c, ipv4("255.255.255.255", 17, 0, 5, udp(1)), pass)
	})
	t.Run("all-64-rules", func(t *testing.T) {
		var rules []testRule
		for i := 0; i < 64; i++ {
			r := testRule{Line: uint32(i + 1), Action: drop, Family: 6, Proto: 17, Matches: 191, Src: prefix("2001:db8::/32"), Dst: prefix("2001:db8::/32"), SportMin: 1, SportMax: 65535, DportMin: 1, DportMax: 65535, SrcSet: 1, DstSet: 2, VLAN: 101}
			rules = append(rules, r)
		}
		rules[63] = testRule{Line: 100, Action: bounce}
		c := loadPolicy(t, cfg(rules...), nil)
		for _, id := range []uint8{1, 2} {
			p := prefix("2001:db8::/32")
			if err := c.Maps["sets"].Put(testSetKey{PrefixLen: 64, Set: id, Family: 6, Bytes: p.Bytes}, uint32(1)); err != nil {
				t.Fatal(err)
			}
		}
		runPacket(t, c, vlan(ipv6("2001:db8::2", 0, chain(8, 17, udp(53))), 100, 0x86dd), bounce)
		if ruleTotals(t, c, 63).Hits != 1 {
			t.Fatal("64th rule not reached")
		}
	})
}

func TestKernelPrefixEdges(t *testing.T) {
	for _, tc := range []struct{ prefix, inside, outside string }{
		{"0.0.0.0/0", "255.255.255.255", "::ffff"},
		{"10.0.128.0/17", "10.0.255.255", "10.0.127.255"},
		{"10.0.0.7/32", "10.0.0.7", "10.1.0.7"},
		{"::/0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "255.255.255.255"},
		{"2001:db8::2/127", "2001:db8::3", "2001:db8::4"},
		{"2001:db8::7/128", "2001:db8::7", "2001:db8:1::7"},
	} {
		t.Run(tc.prefix, func(t *testing.T) {
			c := loadPolicy(t, cfg(testRule{Action: drop, Matches: 1, Src: prefix(tc.prefix)}), nil)
			f := func(src string) []byte {
				if addr(src).Family == 4 {
					return ipv4(src, 17, 0, 5, udp(1))
				}
				return ipv6(src, 17, udp(1))
			}
			runPacket(t, c, f(tc.inside), drop)
			runPacket(t, c, f(tc.outside), pass)
		})
	}
}

func TestKernelActions(t *testing.T) {
	for _, family := range []int{4, 6} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			frame := ipv4("10.1.2.3", 17, 0, 15, udp(53))
			if family == 6 {
				frame = ipv6("2001:db8::2", 0, chain(3, 17, udp(53)))
			}
			frame = vlan(frame, 99, binary.BigEndian.Uint16(frame[12:14]))
			frame = append(frame, []byte("unchanged padding")...)
			c := loadPolicy(t, cfg(testRule{Action: bounce}), nil)
			out := runPacket(t, c, frame, bounce)
			want := append([]byte{}, frame...)
			copy(want[:6], frame[6:12])
			copy(want[6:12], frame[:6])
			if !bytes.Equal(out, want) {
				t.Fatal("bounce changed non-MAC bytes")
			}
			conf := cfg(testRule{Action: honeypot})
			conf.HoneypotIfindex = 1
			c = loadPolicy(t, conf, nil)
			out = runPacket(t, c, frame, honeypot)
			if !bytes.Equal(out, frame) {
				t.Fatal("redirect modified frame")
			}
			if totals(t, c).Honeypotted != 1 {
				t.Fatal("redirect counter")
			}
		})
	}
	t.Run("icmp-fragments-and-fallbacks", func(t *testing.T) {
		c := loadPolicy(t, cfg(testRule{Action: pass, Matches: 64, ICMPType: 128}, testRule{Action: drop, Matches: 128, VLAN: 65535}), nil)
		ping := make([]byte, 8)
		ping[0] = 128
		runPacket(t, c, ipv6("::2", 58, ping), pass)
		runPacket(t, c, ipv4("1.1.1.1", 1, 1, 5, nil), drop)
		conf := cfg()
		conf.FragmentAction = pass
		conf.DefaultAction = drop
		c = loadPolicy(t, conf, nil)
		runPacket(t, c, ipv6("::2", 44, []byte{17, 0, 0, 8, 0, 0, 0, 0}), pass)
		runPacket(t, c, ipv4("1.1.1.1", 17, 0, 5, udp(1)), drop)
		if totals(t, c).DefaultHits != 1 {
			t.Fatal("fragment counted as default")
		}
	})
}

func monotonicNS(t *testing.T) uint64 {
	t.Helper()
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Fatal(err)
	}
	return uint64(ts.Nano())
}

func TestKernelState(t *testing.T) {
	t.Run("jail-real-expiration", func(t *testing.T) {
		c := loadPolicy(t, cfg(testRule{Action: jailAction, JailSeconds: 1, Matches: 32, DportMin: 9, DportMax: 9}), nil)
		runPacket(t, c, ipv6("2001:db8::7", 17, udp(9)), drop)
		time.Sleep(1350 * time.Millisecond)
		runPacket(t, c, ipv6("2001:db8::7", 17, udp(10)), pass)
		healthy(t, c)
	})
	t.Run("limit-sources-rules-refill", func(t *testing.T) {
		r := testRule{Action: limit, Rate: 3, Burst: 3, Matches: 32, DportMin: 1, DportMax: 1}
		r2 := r
		r2.DportMin = 2
		r2.DportMax = 2
		c := loadPolicy(t, cfg(r, r2), nil)
		for _, s := range []string{"10.0.0.7", "10.1.0.7", "2001:db8::7", "2001:db8:1::7"} {
			for _, port := range []uint16{1, 2} {
				f := ipv4("10.0.0.7", 17, 0, 5, udp(port))
				if addr(s).Family == 6 {
					f = ipv6(s, 17, udp(port))
				} else {
					f = ipv4(s, 17, 0, 5, udp(port))
				}
				for i := 0; i < 3; i++ {
					runPacket(t, c, f, pass)
				}
				runPacket(t, c, f, drop)
			}
		}
		time.Sleep(370 * time.Millisecond)
		runPacket(t, c, ipv4("10.0.0.7", 17, 0, 5, udp(1)), pass)
		runPacket(t, c, ipv4("10.0.0.7", 17, 0, 5, udp(1)), drop)
		healthy(t, c)
	})
	t.Run("jail-order-expiry-unjail-later", func(t *testing.T) {
		c := loadPolicy(t, cfg(testRule{Action: jailAction, JailSeconds: 1, Matches: 32, DportMin: 9, DportMax: 9}, testRule{Action: pass}), nil)
		for _, s := range []string{"10.0.0.7", "2001:db8::7"} {
			f := func(port uint16) []byte {
				if addr(s).Family == 4 {
					return ipv4(s, 17, 0, 5, udp(port))
				}
				return ipv6(s, 17, udp(port))
			}
			runPacket(t, c, f(9), drop)
			runPacket(t, c, f(10), drop)
			var value testJail
			if err := c.Maps["jail"].LookupWithFlags(addr(s), &value, ebpf.LookupLock); err != nil {
				t.Fatal(err)
			}
			value.UntilNS = monotonicNS(t) - 1
			if err := c.Maps["jail"].Update(addr(s), value, ebpf.UpdateLock); err != nil {
				t.Fatal(err)
			}
			runPacket(t, c, f(10), pass)
			runPacket(t, c, f(9), drop)
			value.UntilNS = 0
			if err := c.Maps["jail"].Update(addr(s), value, ebpf.UpdateLock); err != nil {
				t.Fatal(err)
			}
			runPacket(t, c, f(10), pass)
		}
		// Malformed validation takes precedence over the jail check.
		runPacket(t, c, ipv4("10.0.0.7", 17, 0, 5, udp(9)), drop)
		runPacket(t, c, ipv4("10.0.0.7", 17, 0, 5, nil), drop)
		if got := totals(t, c); got.Jailed != 2 || got.Malformed != 1 {
			t.Fatalf("jail accounting %+v", got)
		}
		healthy(t, c)
	})
	t.Run("scan-distinct-fixed-window", func(t *testing.T) {
		conf := cfg(testRule{Action: pass})
		conf.ScanPorts = 3
		conf.ScanWindowSeconds = 1
		conf.ScanJailSeconds = 60
		c := loadPolicy(t, conf, nil)
		for _, s := range []string{"10.0.0.7", "2001:db8::7"} {
			f := func(port uint16) []byte {
				if addr(s).Family == 4 {
					return ipv4(s, 17, 0, 5, udp(port))
				}
				return ipv6(s, 17, udp(port))
			}
			for _, port := range []uint16{0, 0, 65535, 65535} {
				runPacket(t, c, f(port), pass)
			}
			runPacket(t, c, f(32768), drop)
			runPacket(t, c, f(0), drop)
		}
		if totals(t, c).Jailed != 4 {
			t.Fatal("scan accounting")
		}
		s := addr("10.0.0.8")
		runPacket(t, c, ipv4("10.0.0.8", 6, 0, 5, tcp(1)), pass)
		var state testScan
		if err := c.Maps["scans"].LookupWithFlags(s, &state, ebpf.LookupLock); err != nil {
			t.Fatal(err)
		}
		state.StartNS = monotonicNS(t) - 2_000_000_000
		if err := c.Maps["scans"].Update(s, state, ebpf.UpdateLock); err != nil {
			t.Fatal(err)
		}
		runPacket(t, c, ipv4("10.0.0.8", 17, 0, 5, udp(2)), pass)
		runPacket(t, c, ipv4("10.0.0.8", 17, 0, 5, udp(3)), pass)
		healthy(t, c)
	})
}

func TestKernelConcurrentAccounting(t *testing.T) {
	c := loadPolicy(t, cfg(testRule{Action: limit, Rate: 1, Burst: 100, Log: 1, Line: 11}), nil)
	frame := ipv6("2001:db8::77", 17, udp(53))
	var wg sync.WaitGroup
	const workers = 4
	const packets = 40000
	var allowed unix.CPUSet
	if err := unix.SchedGetaffinity(0, &allowed); err != nil {
		t.Fatal(err)
	}
	var cpus []int
	for i := 0; i < 1024 && len(cpus) < workers; i++ {
		if allowed.IsSet(i) {
			cpus = append(cpus, i)
		}
	}
	if len(cpus) < workers {
		t.Skip("four allowed CPUs required")
	}
	start := make(chan struct{})
	begin := time.Now()
	for _, cpu := range cpus {
		wg.Add(1)
		go func(cpu int) {
			defer wg.Done()
			// XDP test-run has no RUN_ON_CPU flag (that flag is raw-tracepoint
			// only). Pin four OS threads instead and restore their affinities.
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			var old, selected unix.CPUSet
			if err := unix.SchedGetaffinity(0, &old); err != nil {
				t.Error(err)
				return
			}
			selected.Set(cpu)
			if err := unix.SchedSetaffinity(0, &selected); err != nil {
				t.Error(err)
				return
			}
			defer unix.SchedSetaffinity(0, &old)
			<-start
			for i := 0; i < packets; i++ {
				_, err := c.Programs["trafficcop"].Run(&ebpf.RunOptions{Data: frame, Repeat: 1})
				if err != nil {
					t.Error(err)
					return
				}
			}
		}(cpu)
	}
	close(start)
	wg.Wait()
	sum := totals(t, c)
	if sum.Passed+sum.Dropped != workers*packets || sum.Passed < 100 || sum.Passed > 101+uint64(time.Since(begin).Seconds()) {
		t.Fatalf("shared bucket/counters %+v", sum)
	}
	var count uint64
	if err := c.Maps["sources"].Lookup(addr("2001:db8::77"), &count); err != nil {
		t.Fatal(err)
	}
	if count != workers*packets {
		t.Fatalf("source count %d", count)
	}
	rc := ruleTotals(t, c, 0)
	if rc.Hits != workers*packets || rc.Passed != sum.Passed || rc.Dropped != sum.Dropped {
		t.Fatalf("per-rule accounting %+v", rc)
	}
	healthy(t, c)
	reader, err := ringbuf.NewReader(c.Maps["events"])
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	for i := 0; i < workers*packets; i++ {
		e := readEvent(t, reader)
		if e.Line != 11 || e.Src != addr("2001:db8::77") {
			t.Fatalf("concurrent event %+v", e)
		}
	}
	t.Logf("exact accounting and shared source bucket across CPUs %v", cpus)
}

func TestKernelExactBurstAccounting(t *testing.T) {
	conf := cfg()
	for i, action := range []uint32{pass, drop, bounce, honeypot} {
		conf.Rules[i] = testRule{Action: action, Matches: 32, DportMin: uint16(i + 1), DportMax: uint16(i + 1)}
	}
	conf.RuleCount = 4
	conf.HoneypotIfindex = 1
	c := loadPolicy(t, conf, nil)
	const packets = 100000
	for i, action := range []uint32{pass, drop, bounce, honeypot} {
		verdict := exactAccountingRun(t, c, ipv6("2001:db8::77", 17, udp(uint16(i+1))), packets, nil)
		if verdict != action {
			t.Fatalf("action %d verdict %d", action, verdict)
		}
		r := ruleTotals(t, c, uint32(i))
		if r.Hits != packets || r.Passed+r.Dropped+r.Bounced+r.Honeypotted != packets {
			t.Fatalf("rule %d: %+v", i, r)
		}
	}
	const extra = 1000
	for _, f := range [][]byte{ipv4("10.0.0.1", 17, 0, 5, nil), ethernet(0x0806, make([]byte, 46))} {
		exactAccountingRun(t, c, f, extra, nil)
	}
	sum := totals(t, c)
	if sum.Passed != packets+extra || sum.Dropped != packets+extra || sum.Bounced != packets || sum.Honeypotted != packets || sum.Malformed != extra || sum.Other != extra || sum.DefaultHits != 0 {
		t.Fatalf("exact totals %+v", sum)
	}
	var count uint64
	if err := c.Maps["sources"].Lookup(addr("2001:db8::77"), &count); err != nil {
		t.Fatal(err)
	}
	if count != 4*packets {
		t.Fatalf("source count %d", count)
	}
	healthy(t, c)
}

// A signal can interrupt BPF_PROG_TEST_RUN after some repetitions have already
// changed maps. cilium/ebpf retries the entire Repeat count, not just the missing
// repetitions. Restore the fixture's pre-run accounting in its Reset callback;
// never loosen exact assertions to accommodate partially replayed test traffic.
// This helper is only for these unattached, non-stateful accounting fixtures.
func exactAccountingRun(t *testing.T, c *ebpf.Collection, frame []byte, repeat uint32, onReset func()) uint32 {
	t.Helper()
	var counters []contract.Counters
	if err := c.Maps["counters"].Lookup(uint32(0), &counters); err != nil {
		t.Fatal(err)
	}
	rules := make([][]testRuleCounters, 64)
	for i := range rules {
		if err := c.Maps["rule_counters"].Lookup(uint32(i), &rules[i]); err != nil {
			t.Fatal(err)
		}
	}
	// Sources in this fixture are either the repeated IPv6 source, or invalid/
	// non-IP frames which do not create a source entry.
	src := addr("2001:db8::77")
	var count uint64
	err := c.Maps["sources"].Lookup(src, &count)
	present := err == nil
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatal(err)
	}
	reset := func() {
		if err := c.Maps["counters"].Put(uint32(0), counters); err != nil {
			t.Fatal(err)
		}
		for i, values := range rules {
			if err := c.Maps["rule_counters"].Put(uint32(i), values); err != nil {
				t.Fatal(err)
			}
		}
		if present {
			if err := c.Maps["sources"].Put(src, count); err != nil {
				t.Fatal(err)
			}
		} else if err := c.Maps["sources"].Delete(src); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatal(err)
		}
		if onReset != nil {
			onReset()
		}
	}
	verdict, err := c.Programs["trafficcop"].Run(&ebpf.RunOptions{Data: frame, Repeat: repeat, Reset: reset})
	if err != nil {
		t.Fatal(err)
	}
	return verdict
}

func TestKernelInterruptedBurstAccounting(t *testing.T) {
	c := loadPolicy(t, cfg(testRule{Action: pass}), nil)
	// Warm the library's feature probe before directing a signal at the syscall.
	runPacket(t, c, ethernet(0x0806, make([]byte, 46)), pass)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, unix.SIGUSR1)
	defer signal.Stop(signals)
	tid := unix.Gettid()
	stop := make(chan struct{})
	var once sync.Once
	stopSignals := func() { once.Do(func() { close(stop) }) }
	defer stopSignals()
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				_ = unix.Tgkill(os.Getpid(), tid, unix.SIGUSR1)
			}
		}
	}()
	resets := 0
	const count = 1000000
	verdict := exactAccountingRun(t, c, ipv6("2001:db8::77", 17, udp(1)), count, func() { resets++; stopSignals() })
	stopSignals()
	<-done
	if resets == 0 {
		t.Fatal("signal did not exercise interrupted test-run replay")
	}
	r := ruleTotals(t, c, 0)
	if verdict != pass || r.Hits != count || r.Passed != count {
		t.Fatalf("replayed accounting: verdict=%d counters=%+v", verdict, r)
	}
	var source uint64
	if err := c.Maps["sources"].Lookup(addr("2001:db8::77"), &source); err != nil || source != count {
		t.Fatalf("source=%d err=%v", source, err)
	}
	t.Logf("exact %d decisions after %d interrupted syscall replay(s)", count, resets)
}

func packetSocket(t *testing.T, index int) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(0x0300))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: 0x0300, Ifindex: index}); err != nil {
		t.Fatal(err)
	}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		t.Fatal(err)
	}
	return fd
}
func receiveFrame(t *testing.T, fd int, want []byte) {
	t.Helper()
	buffer := make([]byte, 4096)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n, _, err := unix.Recvfrom(fd, buffer, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) {
				continue
			}
			t.Fatal(err)
		}
		if bytes.Equal(buffer[:n], want) {
			return
		}
	}
	t.Fatalf("expected wire frame not received: %x", want)
}
func readEvent(t *testing.T, reader *ringbuf.Reader) testEvent {
	t.Helper()
	reader.SetDeadline(time.Now().Add(2 * time.Second))
	rec, err := reader.Read()
	if err != nil {
		t.Fatal(err)
	}
	var e testEvent
	if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
		t.Fatal(err)
	}
	return e
}
func TestKernelWireAndReplacement(t *testing.T) {
	if os.Getenv("TC_BPF_NETNS_TEST") != "1" {
		t.Skip("run with bash bpf/netns-test.sh")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	host, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if self == host {
		t.Fatal("refusing to attach in host network namespace")
	}
	eth, err := net.InterfaceByName("eth0")
	if err != nil {
		t.Fatal(err)
	}
	players, err := net.InterfaceByName("players")
	if err != nil {
		t.Fatal(err)
	}
	hp, err := net.InterfaceByName("hp0")
	if err != nil {
		t.Fatal(err)
	}
	trap, err := net.InterfaceByName("trap")
	if err != nil {
		t.Fatal(err)
	}
	peer, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "tc_test_peer", Type: ebpf.XDP, License: "GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, pass), asm.Return()}})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	for _, index := range []int{players.Index, trap.Index} {
		l, err := link.AttachXDP(link.XDPOptions{Program: peer, Interface: index, Flags: link.XDPDriverMode})
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
	}
	conf := cfg(testRule{Action: bounce, Matches: 32, DportMin: 6666, DportMax: 6666, Log: 1, Line: 8}, testRule{Action: honeypot, Matches: 32, DportMin: 7777, DportMax: 7777, Log: 1, Line: 9}, testRule{Action: pass, Matches: 32, DportMin: 9999, DportMax: 9999, Log: 1, Line: 10})
	conf.HoneypotIfindex = uint32(hp.Index)
	c := loadPolicy(t, conf, nil)
	l, err := link.AttachXDP(link.XDPOptions{Program: c.Programs["trafficcop"], Interface: eth.Index, Flags: link.XDPDriverMode})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	reader, err := ringbuf.NewReader(c.Maps["events"])
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	playerFD := packetSocket(t, players.Index)
	ethFD := packetSocket(t, eth.Index)
	trapFD := packetSocket(t, trap.Index)
	wire := func(src string, port uint16) []byte {
		var f []byte
		if addr(src).Family == 4 {
			f = ipv4(src, 17, 0, 15, udp(port))
		} else {
			f = ipv6(src, 0, chain(8, 17, udp(port)))
		}
		copy(f[:6], eth.HardwareAddr)
		copy(f[6:12], players.HardwareAddr)
		return append(f, []byte("trafficcop-wire-test-padding-unchanged")...)
	}
	var backpressure atomic.Uint64
	send := func(fd int, frame []byte) error {
		for attempt := 0; attempt < 100; attempt++ {
			err := unix.Sendto(fd, frame, 0, &unix.SockaddrLinklayer{Ifindex: players.Index, Protocol: 0x0300})
			if !errors.Is(err, unix.ENOBUFS) && !errors.Is(err, unix.EAGAIN) {
				return err
			}
			backpressure.Add(1)
			time.Sleep(time.Millisecond)
		}
		return fmt.Errorf("packet generator remained backpressured after 100 retries")
	}
	for _, s := range []string{"10.1.2.3", "2001:db8::2"} {
		for _, port := range []uint16{6666, 7777, 9999} {
			frame := wire(s, port)
			if err := send(playerFD, frame); err != nil {
				t.Fatal(err)
			}
			want := append([]byte{}, frame...)
			fd := ethFD
			verdict := uint32(pass)
			if port == 6666 {
				copy(want[:6], frame[6:12])
				copy(want[6:12], frame[:6])
				fd = playerFD
				verdict = bounce
			} else if port == 7777 {
				fd = trapFD
				verdict = honeypot
			}
			receiveFrame(t, fd, want)
			e := readEvent(t, reader)
			if e.Verdict != verdict || e.Src != addr(s) {
				t.Fatalf("wire event %+v", e)
			}
		}
	}
	shared := map[string]*ebpf.Map{}
	for _, name := range []string{"counters", "health", "sources", "jail", "events", "maintenance"} {
		shared[name] = c.Maps[name]
	}
	jailKey := addr("10.99.0.1")
	if err := c.Maps["jail"].Put(jailKey, testJail{UntilNS: monotonicNS(t) + 60_000_000_000}); err != nil {
		t.Fatal(err)
	}
	before := totals(t, c)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		fd := packetSocket(t, players.Index)
		wg.Add(1)
		go func() {
			defer wg.Done()
			frame := wire("10.250.0.1", 8888)
			for {
				select {
				case <-stop:
					return
				default:
				}
				for n := 0; n < 16; n++ {
					if err := send(fd, frame); err != nil {
						t.Error(err)
						return
					}
				}
				time.Sleep(2 * time.Millisecond)
			}
		}()
	}
	// Ensure senders finish even on an assertion failure before the normal stop.
	var stopOnce sync.Once
	finish := func() { stopOnce.Do(func() { close(stop) }); wg.Wait() }
	defer finish()
	current := c
	var expectedDrops uint64
	for generation := uint64(2); generation <= 6; generation++ {
		candidate := conf
		candidate.Generation = generation
		if generation%2 == 0 {
			candidate.Rules[2].Action = drop
			expectedDrops++
		}
		next := loadPolicy(t, candidate, shared)
		if got := ruleTotals(t, next, 0); got.Hits != 0 {
			t.Fatal("new generation inherited rule counters")
		}
		if err := l.Update(next.Programs["trafficcop"]); err != nil {
			t.Fatal(err)
		}
		if current != c {
			current.Close()
		}
		current = next
		if err := send(playerFD, wire("10.1.2.3", 9999)); err != nil {
			t.Fatal(err)
		}
		e := readEvent(t, reader)
		if e.Generation != generation || e.Verdict != candidate.Rules[2].Action {
			t.Fatalf("post-publication event %+v, generation %d", e, generation)
		}
		var value testJail
		if err := next.Maps["jail"].LookupWithFlags(jailKey, &value, ebpf.LookupLock); err != nil || value.UntilNS <= monotonicNS(t) {
			t.Fatalf("jail lost on replacement: %+v %v", value, err)
		}
	}
	finish()
	time.Sleep(50 * time.Millisecond)
	after := totals(t, current)
	if after.Dropped-before.Dropped != expectedDrops {
		t.Fatalf("unexpected drops during replacement: before %+v after %+v expected %d", before, after, expectedDrops)
	}
	var flooded uint64
	if err := current.Maps["sources"].Lookup(addr("10.250.0.1"), &flooded); err != nil {
		t.Fatal(err)
	}
	if flooded < 1000 {
		t.Fatalf("insufficient concurrent traffic: %d", flooded)
	}
	healthy(t, current)
	t.Logf("wire-exact IPv4/IPv6 bounce and honeypot; five attached program replacements with %d stable-pass frames and no policy drops; generator backpressure retries=%d", flooded, backpressure.Load())
}

func TestKernelEventBurst(t *testing.T) {
	c := loadPolicy(t, cfg(testRule{Action: drop, Log: 1, Line: 123}), nil)
	r, err := ringbuf.NewReader(c.Maps["events"])
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	const packets = 20000
	frame := ipv6("2001:db8::99", 17, udp(53))
	start := time.Now()
	verdict, err := c.Programs["trafficcop"].Run(&ebpf.RunOptions{Data: frame, Repeat: packets})
	if err != nil {
		t.Fatal(err)
	}
	if verdict != drop {
		t.Fatal("logged drop verdict")
	}
	elapsed := time.Since(start)
	for i := 0; i < packets; i++ {
		r.SetDeadline(time.Now().Add(2 * time.Second))
		rec, err := r.Read()
		if err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
		var e testEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			t.Fatal(err)
		}
		if e.Line != 123 || e.Generation != 1 || e.Src != addr("2001:db8::99") || e.Dport != 53 || e.Verdict != drop {
			t.Fatalf("event %d: %+v", i, e)
		}
	}
	healthy(t, c)
	if totals(t, c).Dropped != packets {
		t.Fatal("event burst packet count")
	}
	t.Logf("%d logged decisions in %s (%.0f/s), all ring events read; not a daemon-drain benchmark", packets, elapsed, float64(packets)/elapsed.Seconds())
}

// Populate on two CPUs when available to expose per-CPU LRU free-node caches.
func populateBucketAcrossCPUs(t *testing.T, m *ebpf.Map, keys []testAddress, values []testBucket) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var old unix.CPUSet
	if err := unix.SchedGetaffinity(0, &old); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.SchedSetaffinity(0, &old); err != nil {
			t.Error(err)
		}
	}()
	var cpus []int
	for cpu := 0; cpu < 1024 && len(cpus) < 2; cpu++ {
		if old.IsSet(cpu) {
			cpus = append(cpus, cpu)
		}
	}
	if len(cpus) == 0 {
		t.Fatal("no allowed CPUs")
	}
	for part, cpu := range cpus {
		var selected unix.CPUSet
		selected.Set(cpu)
		if err := unix.SchedSetaffinity(0, &selected); err != nil {
			t.Fatal(err)
		}
		lo, hi := 0, len(keys)
		if len(cpus) == 2 {
			// Switch off the 128-node batch boundary, leaving free nodes on
			// the first CPU instead of consuming its local cache exactly.
			split := len(keys)/2 + 1
			if part == 0 {
				hi = split
			} else {
				lo = split
			}
		}
		if n, err := m.BatchUpdate(keys[lo:hi], values[lo:hi], nil); err != nil || n != hi-lo {
			t.Fatalf("populate CPU %d: %d %v", cpu, n, err)
		}
	}
}

func TestKernelBucketCapacity(t *testing.T) {
	var rules []testRule
	for i := 0; i < 64; i++ {
		rules = append(rules, testRule{Action: limit, Rate: 1, Burst: 1, Matches: 32, DportMin: uint16(i), DportMax: uint16(i)})
	}
	c := loadPolicy(t, cfg(rules...), nil)
	var allocation uint64
	for i := uint32(0); i < 64; i++ {
		var m *ebpf.Map
		if err := c.Maps["buckets"].Lookup(i, &m); err != nil {
			t.Fatal(err)
		}
		info, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", m.FD()))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(info), "\n") {
			var mem uint64
			if _, err := fmt.Sscanf(line, "memlock: %d", &mem); err == nil {
				allocation += mem
			}
		}
		if i < 2 {
			keys := make([]testAddress, 65536)
			values := make([]testBucket, len(keys))
			for k := range keys {
				keys[k] = testAddress{Family: 4, Bytes: [16]byte{10, byte(i), byte(k >> 8), byte(k)}}
				values[k] = testBucket{NextNS: monotonicNS(t) + 1_000_000_000_000_000}
			}
			populateBucketAcrossCPUs(t, m, keys, values)
			it := m.Iterate()
			count := 0
			var key testAddress
			var value testBucket
			for it.Next(&key, &value) {
				count++
			}
			if err := it.Err(); err != nil {
				t.Fatal(err)
			}
			if count != 65536 {
				t.Fatalf("rule %d retains %d/65536 sources", i, count)
			}
		}
		m.Close()
	}
	for _, i := range []uint16{0, 1} {
		runPacket(t, c, ipv4(fmt.Sprintf("10.%d.0.0", i), 17, 0, 5, udp(i)), drop)
		// Inserting a new source into rule 0 cannot evict rule 1's sources.
		if i == 0 {
			runPacket(t, c, ipv4("192.0.2.1", 17, 0, 5, udp(0)), pass)
		}
	}
	healthy(t, c)
	t.Logf("64 independent limit maps loaded; two retain 65536 sources each; kernel fdinfo memlock sum=%d bytes (includes first-rule template, excludes other maps)", allocation)
}

func TestKernelExpiredStateReclamation(t *testing.T) {
	t.Run("scan-churn-preserves-active", func(t *testing.T) {
		conf := cfg(testRule{Action: pass})
		conf.ScanPorts = 3
		conf.ScanWindowSeconds = 60
		conf.ScanJailSeconds = 60
		c := loadPolicySized(t, conf, nil, 4)
		active := addr("192.0.2.1")
		state := testScan{Generation: 1, StartNS: monotonicNS(t), Count: 1}
		state.Ports[0] = 1 << 7
		if err := c.Maps["scans"].Put(active, state); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			expired := testScan{Generation: 1, StartNS: monotonicNS(t) - 61_000_000_000}
			if err := c.Maps["scans"].Put(addr(fmt.Sprintf("198.51.100.%d", i+1)), expired); err != nil {
				t.Fatal(err)
			}
		}
		for i := 1; i <= 12; i++ {
			source := fmt.Sprintf("203.0.113.%d", i)
			for _, port := range []uint16{10, 11, 12} {
				verdict := uint32(pass)
				if port == 12 {
					verdict = drop
				}
				runPacket(t, c, ipv4(source, 17, 0, 5, udp(port)), verdict)
			}
			// Model expiry while keeping the map full; the next identity must reclaim.
			var scan testScan
			if err := c.Maps["scans"].LookupWithFlags(addr(source), &scan, ebpf.LookupLock); err != nil {
				t.Fatal(err)
			}
			scan.StartNS = monotonicNS(t) - 61_000_000_000
			if err := c.Maps["scans"].Update(addr(source), scan, ebpf.UpdateLock); err != nil {
				t.Fatal(err)
			}
			var jail testJail
			if err := c.Maps["jail"].LookupWithFlags(addr(source), &jail, ebpf.LookupLock); err != nil {
				t.Fatal(err)
			}
			jail.UntilNS = 0
			if err := c.Maps["jail"].Update(addr(source), jail, ebpf.UpdateLock); err != nil {
				t.Fatal(err)
			}
		}
		var kept testScan
		if err := c.Maps["scans"].LookupWithFlags(active, &kept, ebpf.LookupLock); err != nil {
			t.Fatal(err)
		}
		if kept.Count != 1 || kept.Ports[0] != (1<<7) || kept.Retired != 0 {
			t.Fatalf("active scan changed: %+v", kept)
		}
		healthy(t, c)
	})
	t.Run("jail-churn-preserves-active", func(t *testing.T) {
		c := loadPolicySized(t, cfg(testRule{Action: jailAction, JailSeconds: 60, Matches: 32, DportMin: 9, DportMax: 9}), nil, 4)
		active := addr("192.0.2.1")
		keep := testJail{UntilNS: monotonicNS(t) + 60_000_000_000}
		if err := c.Maps["jail"].Put(active, keep); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			if err := c.Maps["jail"].Put(addr(fmt.Sprintf("198.51.100.%d", i+1)), testJail{}); err != nil {
				t.Fatal(err)
			}
		}
		for i := 1; i <= 12; i++ {
			source := fmt.Sprintf("203.0.113.%d", i)
			runPacket(t, c, ipv4(source, 17, 0, 5, udp(9)), drop)
			runPacket(t, c, ipv4(source, 17, 0, 5, udp(10)), drop)
			var jail testJail
			if err := c.Maps["jail"].LookupWithFlags(addr(source), &jail, ebpf.LookupLock); err != nil {
				t.Fatal(err)
			}
			jail.UntilNS = 0
			if err := c.Maps["jail"].Update(addr(source), jail, ebpf.UpdateLock); err != nil {
				t.Fatal(err)
			}
		}
		var kept testJail
		if err := c.Maps["jail"].LookupWithFlags(active, &kept, ebpf.LookupLock); err != nil {
			t.Fatal(err)
		}
		if kept.UntilNS != keep.UntilNS || kept.Retired != 0 {
			t.Fatalf("active jail changed: %+v", kept)
		}
		healthy(t, c)
	})
	t.Run("full-active-scan-fails-closed", func(t *testing.T) {
		conf := cfg()
		conf.ScanPorts = 2
		conf.ScanWindowSeconds = 60
		conf.ScanJailSeconds = 60
		c := loadPolicySized(t, conf, nil, 1)
		runPacket(t, c, ipv4("192.0.2.1", 17, 0, 5, udp(1)), pass)
		runPacket(t, c, ipv4("192.0.2.2", 17, 0, 5, udp(1)), drop)
		if totals(t, c).Jailed != 0 {
			t.Fatal("capacity failure counted as jail")
		}
		runPacket(t, c, ipv4("192.0.2.1", 17, 0, 5, udp(2)), drop)
		if totals(t, c).Jailed != 1 {
			t.Fatal("threshold drop was not accounted as jailed")
		}
	})
}

func TestKernelPendingScanJail(t *testing.T) {
	conf := cfg()
	conf.ScanPorts = 2
	conf.ScanWindowSeconds = 60
	conf.ScanJailSeconds = 60
	c := loadPolicySized(t, conf, nil, 1)
	if err := c.Maps["jail"].Put(addr("198.51.100.1"), testJail{}); err != nil {
		t.Fatal(err)
	}
	// Hold the collector flag: a threshold crossing cannot reclaim a jail slot.
	if err := c.Maps["maintenance"].Put(uint32(0), uint64(1)); err != nil {
		t.Fatal(err)
	}
	frame := func(port uint16) []byte { return ipv4("192.0.2.1", 17, 0, 5, udp(port)) }
	runPacket(t, c, frame(7), pass)
	runPacket(t, c, frame(8), drop)
	// Repeating a known port must remain blocked even without installed jail state.
	runPacket(t, c, frame(7), drop)
	if err := c.Maps["maintenance"].Put(uint32(0), uint64(0)); err != nil {
		t.Fatal(err)
	}
	runPacket(t, c, frame(7), drop)
	var jail testJail
	if err := c.Maps["jail"].LookupWithFlags(addr("192.0.2.1"), &jail, ebpf.LookupLock); err != nil {
		t.Fatal(err)
	}
	if jail.UntilNS <= monotonicNS(t) {
		t.Fatal("pending jail was not retried")
	}
	runPacket(t, c, frame(9), drop)
}

func TestKernelAtomicUnjail(t *testing.T) {
	c := loadPolicySized(t, cfg(testRule{Action: jailAction, JailSeconds: 60, Matches: 32, DportMin: 9, DportMax: 9}), nil, 2)
	type request = contract.UnjailRequest
	command := func(src testAddress) uint32 {
		t.Helper()
		if err := c.Maps["unjail_request"].Put(uint32(0), request{Src: src}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Programs["unjail_command"].Run(&ebpf.RunOptions{Data: make([]byte, 14), Repeat: 1}); err != nil {
			t.Fatal(err)
		}
		var r request
		if err := c.Maps["unjail_request"].Lookup(uint32(0), &r); err != nil {
			t.Fatal(err)
		}
		return r.Result
	}
	src := addr("192.0.2.1")
	if command(src) != 2 {
		t.Fatal("absent source succeeded")
	}
	// A command cannot clear the collector's retirement marker, even if its
	// timestamp appears active (models a stale userspace read before retirement).
	state := testJail{Retired: 1, UntilNS: monotonicNS(t) + 60_000_000_000}
	if err := c.Maps["jail"].Put(src, state); err != nil {
		t.Fatal(err)
	}
	if command(src) != 3 {
		t.Fatal("retired source did not request retry")
	}
	var kept testJail
	if err := c.Maps["jail"].LookupWithFlags(src, &kept, ebpf.LookupLock); err != nil {
		t.Fatal(err)
	}
	if kept.Retired != 1 || kept.UntilNS != state.UntilNS {
		t.Fatal("command revived retired entry")
	}
	state.Retired = 0
	if err := c.Maps["jail"].Update(src, state, ebpf.UpdateLock); err != nil {
		t.Fatal(err)
	}
	if command(src) != 1 {
		t.Fatal("active source was not released")
	}
	runPacket(t, c, ipv4("192.0.2.1", 17, 0, 5, udp(10)), pass)
	// A later kernel jail decision must still take effect; another command
	// releases the latest value without carrying any stale snapshot into a write.
	runPacket(t, c, ipv4("192.0.2.1", 17, 0, 5, udp(9)), drop)
	runPacket(t, c, ipv4("192.0.2.1", 17, 0, 5, udp(10)), drop)
	if command(src) != 1 {
		t.Fatal("new jail was lost")
	}
	runPacket(t, c, ipv4("192.0.2.1", 17, 0, 5, udp(10)), pass)
	healthy(t, c)
}

func TestKernelConcurrentScanFirstTouch(t *testing.T) {
	conf := cfg()
	conf.ScanPorts = 10
	conf.ScanWindowSeconds = 60
	conf.ScanJailSeconds = 60
	c := loadPolicySized(t, conf, nil, 128)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func(port uint16) {
			defer wg.Done()
			<-start
			for source := 1; source <= 64; source++ {
				runPacket(t, c, ipv4(fmt.Sprintf("192.0.2.%d", source), 17, 0, 5, udp(port)), pass)
			}
		}(uint16(worker + 1))
	}
	close(start)
	wg.Wait()
	for source := 1; source <= 64; source++ {
		var state testScan
		if err := c.Maps["scans"].LookupWithFlags(addr(fmt.Sprintf("192.0.2.%d", source)), &state, ebpf.LookupLock); err != nil {
			t.Fatal(err)
		}
		if state.Count != 4 || state.Generation != 1 || state.StartNS == 0 || state.Retired != 0 {
			t.Fatalf("lost first-touch state: %+v", state)
		}
	}
	healthy(t, c)
}

func TestKernelUnjailCancelsPendingScan(t *testing.T) {
	conf := cfg(testRule{Action: jailAction, Proto: 1, JailSeconds: 60})
	conf.ScanPorts = 2
	conf.ScanWindowSeconds = 60
	conf.ScanJailSeconds = 60
	c := loadPolicySized(t, conf, nil, 1)
	src := addr("192.0.2.1")
	if err := c.Maps["jail"].Put(addr("198.51.100.1"), testJail{}); err != nil {
		t.Fatal(err)
	}
	if err := c.Maps["maintenance"].Put(uint32(0), uint64(1)); err != nil {
		t.Fatal(err)
	}
	frame := func(port uint16) []byte { return ipv4("192.0.2.1", 17, 0, 5, udp(port)) }
	runPacket(t, c, frame(7), pass)
	runPacket(t, c, frame(8), drop)
	if err := c.Maps["maintenance"].Put(uint32(0), uint64(0)); err != nil {
		t.Fatal(err)
	}
	runPacket(t, c, ipv4("192.0.2.1", 1, 0, 5, make([]byte, 8)), drop)
	type request = contract.UnjailRequest
	if err := c.Maps["unjail_request"].Put(uint32(0), request{Src: src}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Programs["unjail_command"].Run(&ebpf.RunOptions{Data: make([]byte, 14)}); err != nil {
		t.Fatal(err)
	}
	var result request
	if err := c.Maps["unjail_request"].Lookup(uint32(0), &result); err != nil {
		t.Fatal(err)
	}
	if result.Result != 1 {
		t.Fatalf("unjail result %d", result.Result)
	}
	runPacket(t, c, frame(7), pass)
	runPacket(t, c, frame(7), pass)
	// A fresh distinct port is a new threshold decision and may jail again.
	runPacket(t, c, frame(9), drop)
}

func TestKernelCancellationReclamation(t *testing.T) {
	c := loadPolicySized(t, cfg(testRule{Action: jailAction, JailSeconds: 60}), nil, 1)
	old := addr("192.0.2.1")
	state := testJail{CancelledNS: monotonicNS(t)}
	if err := c.Maps["jail"].Put(old, state); err != nil {
		t.Fatal(err)
	}
	frame := ipv4("192.0.2.2", 17, 0, 5, udp(9))
	runPacket(t, c, frame, drop)
	var kept testJail
	if err := c.Maps["jail"].LookupWithFlags(old, &kept, ebpf.LookupLock); err != nil {
		t.Fatal("live cancellation reclaimed:", err)
	}
	t.Run("hour-old-cancellation", func(t *testing.T) {
		// A fresh runner cannot contain an hour-old monotonic timestamp.
		// Do not wrap uint64 into a future time to fabricate one. The live
		// cancellation assertion above still executes on every host.
		const aged = uint64(contract.MaxJailSeconds+1) * uint64(time.Second)
		now := monotonicNS(t)
		if now <= aged {
			t.Skip("host monotonic uptime is too short for an hour-old cancellation fixture")
		}
		state.CancelledNS = now - aged
		if err := c.Maps["jail"].Update(old, state, ebpf.UpdateLock); err != nil {
			t.Fatal(err)
		}
		runPacket(t, c, frame, drop)
		if err := c.Maps["jail"].LookupWithFlags(addr("192.0.2.2"), &kept, ebpf.LookupLock); err != nil {
			t.Fatal("expired cancellation was not reclaimed:", err)
		}
		if kept.UntilNS <= monotonicNS(t) {
			t.Fatal("new jail not installed")
		}
	})
}
