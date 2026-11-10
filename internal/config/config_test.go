package config

import (
	"fmt"
	"golang.org/x/sys/unix"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TANKominator5/BytecodeBouncer/internal/contract"
)

func TestCompleteGrammar(t *testing.T) {
	input := `# comment
default drop
fragments pass
drop src @later log
set empty
set later 10.0.0.5/24 10.0.0.0/24 2001:db8:1::f/48
set later 192.0.2.7
portscan 20 ports in 5s jail 60
limit 1000000/s burst 1000000 proto icmp6 icmp-type 255 family ipv6 vlan any
jail 3600 sport 0-65535 dport 65535 dst @later
bounce family any proto any vlan none
honeypot src ::/0 dst 0.0.0.0/0
pass vlan 4095
`
	p, err := ParseReader(strings.NewReader(input), true)
	if err != nil {
		t.Fatal(err)
	}
	if p.Config.DefaultAction != contract.Drop || p.Config.FragmentAction != contract.Pass || p.Config.RuleCount != 6 {
		t.Fatalf("config %+v", p.Config)
	}
	if p.Config.Rules[0].Line != 4 || p.Config.Rules[0].SrcSet != 1 || p.Config.Rules[0].Matches != contract.SrcSet || p.Config.Rules[0].Log != 1 {
		t.Fatalf("forward ref %+v", p.Config.Rules[0])
	}
	if len(p.Sets[0].Prefixes) != 0 || len(p.Sets[1].Prefixes) != 3 {
		t.Fatalf("normalized sets %+v", p.Sets)
	}
	if _, ok := p.Sets[1].Prefixes[netip.MustParsePrefix("10.0.0.0/24")]; !ok {
		t.Fatal("host bits not cleared")
	}
	if p.Config.Rules[1].Matches&contract.VLAN != 0 || p.Config.Rules[3].VLAN != contract.VLANNone {
		t.Fatal("VLAN any/none")
	}
	if p.Config.Rules[4].Src.Family != 6 || p.Config.Rules[4].Dst.Family != 4 {
		t.Fatal("prefix families")
	}
}
func TestRejectWholeFile(t *testing.T) {
	cases := []string{
		"default pass\ndefault drop", "fragments pass\nfragments pass", "default bounce", "default pass extra",
		"portscan 2 ports in 1s jail 1\nportscan 2 ports in 1s jail 1", "portscan 1 ports in 1s jail 1",
		"portscan 1001 ports in 1s jail 1", "portscan 2 ports in 61s jail 1", "portscan 2 ports in 1s jail 3601",
		"portscan 2 ports in 1/s jail 1", "portscan 2 port in 1s jail 1", "drop src @unknown", "set Bad 10.0.0.1",
		"set " + strings.Repeat("a", 33), "set x 10.0.0.1/33", "set x fe80::1%eth0", "drop src @", "drop src @x\nset x invalid",
		"drop src 10.0.0.1 src ::1", "pass proto udp proto tcp", "pass family any family ipv4", "pass vlan any vlan none",
		"pass log log", "pass sport 1 sport 2", "pass icmp-type 0 icmp-type 1", "drop src", "drop dst invalid",
		"drop sport -1", "drop sport +1", "drop dport 2-1", "drop dport 1-2-3", "drop dport 65536",
		"drop proto 17", "pass family ip", "pass vlan -1", "pass vlan 4096", "pass icmp-type 256",
		"limit 0/s burst 1", "limit 1/s burst 0", "limit 1000001/s burst 1", "limit 1/s burst 1000001",
		"limit 1 burst 1", "limit 1/s 1", "jail 0", "jail 3601", "jail", "bounce unexpected value",
		"PASS", "pass\vproto udp", "pass\u00a0proto udp", "set", "defaut pass",
	}
	for _, input := range cases {
		t.Run(input, func(t *testing.T) {
			p, err := ParseReader(strings.NewReader("# line 1\n\n"+input), true)
			if err == nil || p != nil || !strings.Contains(err.Error(), "line ") {
				t.Fatalf("accepted invalid file: %q %+v %v", input, p, err)
			}
		})
	}
	if _, err := ParseReader(strings.NewReader("# hi\n\nhoneypot log"), false); err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Fatal(err)
	}
}
func TestCountsAndBoundaries(t *testing.T) {
	for _, n := range []int{64, 65} {
		_, err := ParseReader(strings.NewReader(strings.Repeat("pass\n", n)), false)
		if (err == nil) != (n == 64) {
			t.Fatalf("%d rules: %v", n, err)
		}
	}
	for _, n := range []int{16, 17} {
		var b strings.Builder
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "set s%d\n", i)
		}
		_, err := ParseReader(strings.NewReader(b.String()), false)
		if (err == nil) != (n == 16) {
			t.Fatalf("%d sets: %v", n, err)
		}
	}
	var b strings.Builder
	b.WriteString("set hosts")
	for i := 0; i < 10000; i++ {
		fmt.Fprintf(&b, " 10.0.%d.%d", i>>8, i&255)
	}
	if _, err := ParseReader(strings.NewReader(b.String()), false); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseReader(strings.NewReader(b.String()+" 192.0.2.1"), false); err == nil {
		t.Fatal("accepted 10001 prefixes")
	}
	if _, err := ParseReader(strings.NewReader("# windows\r\n\tdefault\tpass\r\n"), false); err != nil {
		t.Fatal(err)
	}
}
func TestBinaryAddresses(t *testing.T) {
	for _, s := range []string{"192.0.2.9", "2001:db8::9", "::ffff:192.0.2.9"} {
		a := netip.MustParseAddr(s)
		got := Address(a)
		if (got.Family == 4) != a.Is4() {
			t.Fatal("family was collapsed")
		}
		p, err := Prefix(s)
		if err != nil {
			t.Fatal(err)
		}
		key := SetKey(3, p)
		if key.Set != 3 || key.PrefixLen != 32+uint32(a.BitLen()) || key.Family != got.Family || key.Bytes != got.Bytes {
			t.Fatalf("key %+v", key)
		}
	}
}

func TestRuntimePolicyFiles(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fifo, "/dev/zero", dir} {
		if _, err := Parse(path, false); err == nil {
			t.Fatalf("accepted special file %s", path)
		}
	}
	if _, err := Parse("/dev/null", false); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy")
	for _, input := range []string{"# comment\npass log", strings.Repeat("#\n", (16<<20)/2+1)} {
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(path, false); err == nil {
			t.Fatal("accepted unsupported or oversized policy")
		}
	}
	if err := os.WriteFile(path, []byte("default drop\npass src ::1"), 0600); err != nil {
		t.Fatal(err)
	}
	policy, err := Parse(path, false)
	if err != nil || policy.Config.RuleCount != 1 {
		t.Fatalf("regular policy: %v %+v", err, policy)
	}
}
