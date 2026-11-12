//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TANKominator5/BytecodeBouncer/internal/config"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestKernelRetiredGenerationObjects(t *testing.T) {
	if os.Getenv("TC_BPF_ENDURANCE") != "1" {
		t.Skip("set TC_BPF_ENDURANCE=1 for repeated full-policy resource checks")
	}
	p := productionPlane(t, "default pass\n")
	shared := make(map[string]*ebpf.Map)
	persistent := make(map[ebpf.MapID]bool)
	for _, name := range []string{"counters", "health", "maintenance", "sources", "jail", "events"} {
		m := p.collection.Maps[name]
		shared[name] = m
		info, err := m.Info()
		if err != nil {
			t.Fatal(err)
		}
		id, _ := info.ID()
		persistent[id] = true
	}
	retiredMaps := make(map[ebpf.MapID]bool)
	retiredPrograms := make(map[ebpf.ProgramID]bool)
	var maxPrepare time.Duration
	for generation := 0; generation < 30; generation++ {
		var input strings.Builder
		input.WriteString("default pass\n")
		for i := 0; i < 64; i++ {
			fmt.Fprintf(&input, "limit %d/s burst %d family ipv6 proto udp src 2001:db8::/32 dst 2001:db8::/32 sport 40000 dport %d vlan none\n", 1000000-generation, 1000000-generation, 10000+i)
		}
		policy, err := config.ParseReader(strings.NewReader(input.String()), false)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		c, _, err := p.prepare(policy, uint64(generation+2), shared)
		elapsed := time.Since(start)
		if err != nil {
			t.Fatal(err)
		}
		if elapsed > maxPrepare {
			maxPrepare = elapsed
		}
		runPacket(t, c, ipv6("2001:db8::7", 60, chain(8, 17, udp(10063))), pass)
		for _, m := range c.Maps {
			info, err := m.Info()
			if err != nil {
				t.Fatal(err)
			}
			id, _ := info.ID()
			if !persistent[id] {
				retiredMaps[id] = true
			}
		}
		for i := uint32(0); i < 64; i++ {
			var id ebpf.MapID
			if err := c.Maps["buckets"].Lookup(i, &id); err != nil {
				t.Fatal(err)
			}
			retiredMaps[id] = true
		}
		for _, prog := range c.Programs {
			info, err := prog.Info()
			if err != nil {
				t.Fatal(err)
			}
			id, _ := info.ID()
			retiredPrograms[id] = true
		}
		c.Close()
	}
	start := time.Now()
	deadline := start.Add(5 * time.Second)
	for {
		for id := range retiredPrograms {
			prog, err := ebpf.NewProgramFromID(id)
			if err == nil {
				prog.Close()
			} else if errors.Is(err, unix.ENOENT) {
				delete(retiredPrograms, id)
			} else {
				t.Fatal(err)
			}
		}
		for id := range retiredMaps {
			m, err := ebpf.NewMapFromID(id)
			if err == nil {
				m.Close()
			} else if errors.Is(err, unix.ENOENT) {
				delete(retiredMaps, id)
			} else {
				t.Fatal(err)
			}
		}
		if len(retiredMaps) == 0 && len(retiredPrograms) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("retained %d private maps/%d programs after descriptors closed", len(retiredMaps), len(retiredPrograms))
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Logf("30 changed full 64-limit policies (IPv6 prefixes/ports/VLAN/eight extensions): max prepare=%s; all retired private/inner maps and programs unreachable by kernel ID after %s", maxPrepare, time.Since(start))
}
