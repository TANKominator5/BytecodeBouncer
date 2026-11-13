//go:build linux

package dataplane

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TANKominator5/BytecodeBouncer/internal/contract"
	"github.com/TANKominator5/BytecodeBouncer/internal/observe"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func capacityAddress(i int) contract.Address {
	a := contract.Address{Family: 6, Bytes: [16]byte{0xfd}}
	binary.BigEndian.PutUint64(a.Bytes[8:], uint64(i+1))
	return a
}

func TestKernelFullSnapshotLatency(t *testing.T) {
	if os.Getenv("TC_BPF_CAPACITY") != "1" {
		t.Skip("set TC_BPF_CAPACITY=1 for million-source/jail snapshot")
	}
	requireBPF(t)
	if availableMemory(t) < 1536<<20 {
		t.Fatal("full snapshot test needs 1.5 GiB available")
	}
	p := productionPlane(t, "default pass\n"+strings.Repeat("pass\n", 64))
	const count = 1048576
	keys := make([]contract.Address, 1024)
	values := make([]uint64, len(keys))
	jails := make([]contract.JailValue, len(keys))
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		t.Fatal(err)
	}
	for offset := 0; offset < count; offset += len(keys) {
		for i := range keys {
			keys[i] = capacityAddress(offset + i)
			values[i] = uint64(offset + i + 1)
			jails[i] = contract.JailValue{UntilNS: uint64(now.Nano()) + uint64(time.Hour)}
		}
		if n, err := p.collection.Maps["sources"].BatchUpdate(keys, values, nil); err != nil || n != len(keys) {
			t.Fatalf("sources %d %v", n, err)
		}
		if n, err := p.collection.Maps["jail"].BatchUpdate(keys, jails, nil); err != nil || n != len(keys) {
			t.Fatalf("jail %d %v", n, err)
		}
	}
	for i := 0; i < 3; i++ {
		start := time.Now()
		s, err := observe.Snapshot(p)
		elapsed := time.Since(start)
		if err != nil || s.JailedSources != count || len(s.Rules) != 64 || len(s.TopSources) != 5 || s.TopSources[0].Packets != count {
			t.Fatalf("snapshot jail=%d top=%+v err=%v", s.JailedSources, s.TopSources, err)
		}
		t.Logf("full source+jail capacity snapshot %d: %s", i, elapsed)
		if elapsed >= time.Second {
			t.Errorf("full stats snapshot exceeded command budget: %s", elapsed)
		}
	}
}

func availableMemory(t *testing.T) uint64 {
	t.Helper()
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "MemAvailable:" {
			kb, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			return kb * 1024
		}
	}
	t.Fatal("missing MemAvailable")
	return 0
}

func mapMemlock(t *testing.T, m *ebpf.Map) uint64 {
	t.Helper()
	data, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", m.FD()))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "memlock:" {
			value, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			return value
		}
	}
	t.Fatal("missing map memlock accounting")
	return 0
}

// Consequential memory/pressure checks, deliberately separate from smoke CI.
// Fill real production capacities, not the reduced maps used by fast fixtures.
func TestKernelFullStateCapacity(t *testing.T) {
	if os.Getenv("TC_BPF_CAPACITY") != "1" {
		t.Skip("set TC_BPF_CAPACITY=1; requires at least 1.5 GiB available")
	}
	requireBPF(t)
	if availableMemory(t) < 1536<<20 {
		t.Fatal("full-capacity test needs 1.5 GiB available; refusing host memory pressure")
	}
	for _, name := range []string{"sources", "jail", "scans"} {
		t.Run(name, func(t *testing.T) {
			rules := "default pass\n"
			if name == "jail" {
				rules += "jail 3600\n"
			}
			if name == "scans" {
				rules += "portscan 2 ports in 60s jail 60\n"
			}
			p := productionPlane(t, rules)
			m := p.collection.Maps[name]
			info, err := m.Info()
			if err != nil {
				t.Fatal(err)
			}
			count := int(info.MaxEntries)
			if name == "scans" && count != 65536 || name != "scans" && count != 1048576 {
				t.Fatal("not production capacity", count)
			}
			var now unix.Timespec
			if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
				t.Fatal(err)
			}
			until := uint64(now.Nano()) + uint64(time.Hour)
			before := availableMemory(t)
			start := time.Now()
			keys := make([]contract.Address, 1024)
			sources := make([]uint64, len(keys))
			jails := make([]contract.JailValue, len(keys))
			scans := make([]contract.ScanValue, len(keys))
			for offset := 0; offset < count; offset += len(keys) {
				n := min(len(keys), count-offset)
				for i := 0; i < n; i++ {
					keys[i] = capacityAddress(offset + i)
					sources[i] = 1
					jails[i] = contract.JailValue{UntilNS: until}
					scans[i] = contract.ScanValue{Count: 1, Generation: 1, StartNS: uint64(now.Nano()), Ports: [1024]uint64{2}}
				}
				var values interface{}
				switch name {
				case "sources":
					values = sources[:n]
				case "jail":
					values = jails[:n]
				case "scans":
					values = scans[:n]
				}
				written, err := m.BatchUpdate(keys[:n], values, nil)
				if err != nil || written != n {
					t.Fatalf("fill offset=%d count=%d err=%v", offset, written, err)
				}
			}
			fill := time.Since(start)
			after := availableMemory(t)
			t.Logf("capacity=%d map_fdinfo_memlock_bytes=%d host_MemAvailable_delta_bytes=%d fill=%s (host delta is not isolated map RSS)", count, mapMemlock(t, m), int64(before)-int64(after), fill)
			newSource := "fd01::1"
			start = time.Now()
			want := uint32(pass)
			if name != "sources" {
				want = drop
			}
			runPacket(t, p.collection, ipv6(newSource, 17, udp(1)), want)
			t.Logf("full-active pressure verdict latency: %s", time.Since(start))
			health, err := p.ReadHealth()
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "sources":
				if health.SourceFull != 1 {
					t.Fatalf("health %+v", health)
				}
				if err := m.Delete(capacityAddress(0)); err != nil {
					t.Fatal(err)
				}
			case "jail":
				if health.JailFull != 1 {
					t.Fatalf("health %+v", health)
				}
				var active contract.JailValue
				if err := m.LookupWithFlags(capacityAddress(count-1), &active, ebpf.LookupLock); err != nil || active.UntilNS != until {
					t.Fatalf("active jail evicted: %+v %v", active, err)
				}
				if err := m.Put(capacityAddress(0), contract.JailValue{UntilNS: 1}); err != nil {
					t.Fatal(err)
				}
			case "scans":
				if health.ScanFull != 1 {
					t.Fatalf("health %+v", health)
				}
				var active contract.ScanValue
				if err := m.LookupWithFlags(capacityAddress(count-1), &active, ebpf.LookupLock); err != nil || active.Count != 1 {
					t.Fatalf("active scan evicted: %+v %v", active, err)
				}
				if err := m.Put(capacityAddress(0), contract.ScanValue{Generation: 0}); err != nil {
					t.Fatal(err)
				}
			}
			start = time.Now()
			collectRequested(t, p.collection)
			t.Logf("off-packet recovery sweep latency: %s", time.Since(start))
			start = time.Now()
			want = pass
			if name == "jail" {
				want = drop
			}
			runPacket(t, p.collection, ipv6(newSource, 17, udp(1)), want)
			t.Logf("capacity-recovery verdict latency: %s", time.Since(start))
			key := addr(newSource)
			switch name {
			case "sources":
				var value uint64
				if err := m.Lookup(key, &value); err != nil || value != 1 {
					t.Fatalf("source recovery %d %v", value, err)
				}
			case "jail":
				var value contract.JailValue
				if err := m.LookupWithFlags(key, &value, ebpf.LookupLock); err != nil || value.UntilNS == 0 {
					t.Fatalf("jail recovery %+v %v", value, err)
				}
			case "scans":
				var value contract.ScanValue
				if err := m.LookupWithFlags(key, &value, ebpf.LookupLock); err != nil || value.Count != 1 {
					t.Fatalf("scan recovery %+v %v", value, err)
				}
			}
			recovered, err := p.ReadHealth()
			if err != nil || recovered != health {
				t.Fatalf("recovery continued failing: %+v -> %+v (%v)", health, recovered, err)
			}
		})
	}
}
