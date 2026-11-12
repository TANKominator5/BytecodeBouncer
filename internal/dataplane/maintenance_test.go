//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TANKominator5/BytecodeBouncer/internal/contract"
	"github.com/cilium/ebpf"
)

func collectRequested(t *testing.T, c *ebpf.Collection) {
	t.Helper()
	for _, name := range []string{"reclaim_jail_command", "reclaim_scan_command"} {
		if _, err := c.Programs[name].Run(&ebpf.RunOptions{Data: make([]byte, 14), Repeat: 1}); err != nil {
			t.Error(err)
			return
		}
	}
}

func TestKernelSustainedActivePressure(t *testing.T) {
	if os.Getenv("TC_PRESSURE_TEST") != "1" {
		t.Skip("set TC_PRESSURE_TEST=1 for two-second full-active pressure per map")
	}
	for _, name := range []string{"jail", "scans"} {
		t.Run(name, func(t *testing.T) {
			const entries = 8192
			conf := cfg(testRule{Action: jailAction, JailSeconds: 60})
			if name == "scans" {
				conf = cfg()
				conf.ScanPorts = 3
				conf.ScanWindowSeconds = 3600
				conf.ScanJailSeconds = 60
			}
			c := loadPolicySized(t, conf, nil, entries)
			until := monotonicNS(t) + uint64(time.Hour)
			for i := 0; i < entries; i++ {
				var err error
				if name == "jail" {
					err = c.Maps[name].Put(capacityAddress(i), testJail{UntilNS: until})
				} else {
					err = c.Maps[name].Put(capacityAddress(i), testScan{Generation: 1, StartNS: until - uint64(time.Hour), Count: 1})
				}
				if err != nil {
					t.Fatalf("fill %s offset=%d: %v", name, i, err)
				}
			}
			p := &Plane{collection: c}
			p.startMaintenance()
			defer p.Close()
			var packets atomic.Uint64
			var wg sync.WaitGroup
			stop := make(chan struct{})
			samples := make(chan []time.Duration, 4)
			start := time.Now()
			for worker := 0; worker < 4; worker++ {
				wg.Add(1)
				go func(worker int) {
					defer wg.Done()
					var latencies []time.Duration
					defer func() { samples <- latencies }()
					for i := 1; ; i++ {
						select {
						case <-stop:
							return
						default:
						}
						frame := ipv6(fmt.Sprintf("fd01:%x::%x:%x", worker, i>>16, i&65535), 17, udp(1))
						before := time.Now()
						v, _, err := c.Programs["trafficcop"].Test(frame)
						elapsed := time.Since(before)
						if err != nil || v != drop {
							t.Errorf("pressure verdict=%d err=%v", v, err)
							return
						}
						packets.Add(1)
						if i%64 == 1 {
							latencies = append(latencies, elapsed)
						}
					}
				}(worker)
			}
			time.Sleep(2 * time.Second)
			close(stop)
			wg.Wait()
			elapsed := time.Since(start)
			close(p.maintenanceStop)
			<-p.maintenanceDone
			p.maintenanceStop = nil
			var latencies []time.Duration
			for i := 0; i < 4; i++ {
				latencies = append(latencies, (<-samples)...)
			}
			sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
			n := packets.Load()
			if n == 0 || len(latencies) == 0 {
				t.Fatal("no pressure traffic")
			}
			counters := totals(t, c)
			if counters.Dropped != n || counters.Passed != 0 || counters.Jailed != 0 {
				t.Fatal("pressure accounting", counters, n)
			}
			h, err := p.ReadHealth()
			if err != nil {
				t.Fatal(err)
			}
			if name == "jail" && h.JailFull != n || name == "scans" && h.ScanFull != n {
				t.Fatal("pressure diagnostics", h, n)
			}
			h.JailFull = 0
			h.ScanFull = 0
			if h != (contract.Health{}) {
				t.Fatal("unexpected pressure diagnostics", h)
			}
			if name == "jail" {
				var v testJail
				if err := c.Maps[name].LookupWithFlags(capacityAddress(0), &v, ebpf.LookupLock); err != nil || v.UntilNS != until || v.Retired != 0 {
					t.Fatal("active state changed", err)
				}
			} else {
				var v testScan
				if err := c.Maps[name].LookupWithFlags(capacityAddress(0), &v, ebpf.LookupLock); err != nil || v.Count != 1 || v.Retired != 0 {
					t.Fatal("active state changed", err)
				}
			}
			t.Logf("%s: entries=%d workers=4 (not CPU count) packets=%d seconds=%.3f test-run pps=%.0f sample-every-64 p50=%s p95=%s p99=%s max=%s; exact drops/diagnostics, active state preserved; worker running", name, entries, n, elapsed.Seconds(), float64(n)/elapsed.Seconds(), latencies[len(latencies)/2], latencies[len(latencies)*95/100], latencies[len(latencies)*99/100], latencies[len(latencies)-1])
		})
	}
}

func TestKernelCollectorPinsRetiredGeneration(t *testing.T) {
	conf := cfg()
	conf.ScanPorts = 3
	conf.ScanWindowSeconds = 60
	conf.ScanJailSeconds = 60
	old := loadPolicySized(t, conf, nil, 2)
	for i := 0; i < 2; i++ {
		if err := old.Maps["scans"].Put(capacityAddress(i), testScan{}); err != nil {
			t.Fatal(err)
		}
	}
	runPacket(t, old, ipv6("fd01::1", 17, udp(1)), drop)
	p := &Plane{collection: old}
	programs, err := p.maintenancePrograms()
	if err != nil || len(programs) != 1 {
		t.Fatal(len(programs), err)
	}
	defer func() {
		for _, prog := range programs {
			prog.Close()
		}
	}()
	shared := make(map[string]*ebpf.Map)
	for _, name := range []string{"maintenance", "jail", "counters", "health", "sources", "events"} {
		shared[name] = old.Maps[name]
	}
	conf.Generation = 2
	next := loadPolicySized(t, conf, shared, 2)
	keep := testScan{Generation: 2, StartNS: monotonicNS(t), Count: 1}
	if err := next.Maps["scans"].Put(capacityAddress(0), keep); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.collection = next
	p.mu.Unlock()
	old.Close()
	for _, prog := range programs {
		if _, err := prog.Run(&ebpf.RunOptions{Data: make([]byte, 14), Repeat: 1}); err != nil {
			t.Fatal("retired collector lost pinned maps", err)
		}
	}
	var got testScan
	if err := next.Maps["scans"].LookupWithFlags(capacityAddress(0), &got, ebpf.LookupLock); err != nil || got != keep {
		t.Fatal("old collector changed new generation", got.Count, err)
	}
}

func TestKernelCollectorBatchAndCoalescing(t *testing.T) {
	for _, name := range []string{"jail", "scans"} {
		t.Run(name, func(t *testing.T) {
			conf := cfg(testRule{Action: jailAction, JailSeconds: 60})
			if name == "scans" {
				conf = cfg()
				conf.ScanPorts = 3
				conf.ScanWindowSeconds = 60
				conf.ScanJailSeconds = 60
			}
			c := loadPolicySized(t, conf, nil, 320)
			kind := uint32(0)
			if name == "scans" {
				kind = 1
			}
			for i := 0; i < 320; i++ {
				var err error
				if name == "jail" {
					err = c.Maps[name].Put(capacityAddress(i), testJail{})
				} else {
					err = c.Maps[name].Put(capacityAddress(i), testScan{})
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 20; i++ {
				runPacket(t, c, ipv6(fmt.Sprintf("fd01::%x", i+1), 17, udp(1)), drop)
			}
			var state uint64
			if err := c.Maps["maintenance"].Lookup(kind, &state); err != nil || state != contract.GCRequested {
				t.Fatal("requests not coalesced", state, err)
			}
			collectRequested(t, c)
			count := func() int {
				t.Helper()
				var next testAddress
				n := 0
				var previous any
				for {
					err := c.Maps[name].NextKey(previous, &next)
					if errors.Is(err, ebpf.ErrKeyNotExist) {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					n++
					previous = next
				}
				return n
			}
			if n := count(); n != 320-contract.GCBatch {
				t.Fatalf("collector batch=%d", 320-n)
			}
			collectRequested(t, c)
			if n := count(); n != 320-contract.GCBatch {
				t.Fatal("idle collector deleted more entries", n)
			}
			if err := c.Maps["maintenance"].Lookup(kind, &state); err != nil || state != contract.GCIdle {
				t.Fatal(state, err)
			}
		})
	}
}

func TestKernelAsyncMaintenanceLifecycle(t *testing.T) {
	conf := cfg(testRule{Action: jailAction, JailSeconds: 60})
	c := loadPolicySized(t, conf, nil, 2)
	p := &Plane{collection: c}
	p.startMaintenance()
	t.Cleanup(func() { p.Close() })
	for i := 0; i < 2; i++ {
		if err := c.Maps["jail"].Put(capacityAddress(i), testJail{}); err != nil {
			t.Fatal(err)
		}
	}
	frame := ipv6("fd01::1", 17, udp(1))
	runPacket(t, c, frame, drop)
	deadline := time.Now().Add(time.Second)
	for {
		var value testJail
		if err := c.Maps["jail"].Lookup(addr("fd01::1"), &value); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker did not recover capacity")
		}
		time.Sleep(time.Millisecond)
		runPacket(t, c, frame, drop)
	}
	if _, err := p.ReadHealth(); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.maintenanceDone:
	default:
		t.Fatal("worker survived Close")
	}
}

func TestKernelMaintenanceFailureVisible(t *testing.T) {
	c := loadPolicySized(t, cfg(), nil, 2)
	if err := c.Programs["reclaim_jail_command"].Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Maps["maintenance"].Put(uint32(0), contract.GCRequested); err != nil {
		t.Fatal(err)
	}
	p := &Plane{collection: c}
	p.startMaintenance()
	defer p.Close()
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := p.ReadHealth(); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("maintenance failure was hidden")
		}
		time.Sleep(time.Millisecond)
	}
	if err := c.Maps["maintenance"].Put(uint32(0), contract.GCIdle); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * maintenanceInterval)
	if _, err := p.ReadHealth(); err == nil {
		t.Fatal("idle tick erased maintenance failure")
	}
}

func TestKernelConcurrentAsyncReclamation(t *testing.T) {
	for _, name := range []string{"jail", "scans"} {
		t.Run(name, func(t *testing.T) {
			conf := cfg(testRule{Action: jailAction, JailSeconds: 60})
			if name == "scans" {
				conf = cfg()
				conf.ScanPorts = 3
				conf.ScanWindowSeconds = 60
				conf.ScanJailSeconds = 60
			}
			c := loadPolicySized(t, conf, nil, 64)
			until := monotonicNS(t) + uint64(time.Hour)
			for i := 0; i < 64; i++ {
				var err error
				if name == "jail" {
					v := testJail{}
					if i == 0 {
						v.UntilNS = until
					}
					err = c.Maps[name].Put(capacityAddress(i), v)
				} else {
					v := testScan{}
					if i == 0 {
						v.Generation = 1
						v.StartNS = monotonicNS(t)
						v.Count = 1
						v.Ports[0] = 2
					}
					err = c.Maps[name].Put(capacityAddress(i), v)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			var wg sync.WaitGroup
			stop := make(chan struct{})
			done := make(chan struct{})
			go func() {
				defer close(done)
				for {
					select {
					case <-stop:
						return
					default:
						collectRequested(t, c)
						time.Sleep(time.Millisecond)
					}
				}
			}()
			for worker := 0; worker < 4; worker++ {
				wg.Add(1)
				go func(worker int) {
					defer wg.Done()
					for i := 0; i < 100; i++ {
						frame := ipv6(fmt.Sprintf("fd01::%x", worker*100+i+1), 17, udp(1))
						v, _, err := c.Programs["trafficcop"].Test(frame)
						if err != nil {
							t.Error(err)
							return
						}
						if name == "jail" && v != drop || name == "scans" && v != pass && v != drop {
							t.Errorf("unexpected verdict %d", v)
							return
						}
					}
				}(worker)
			}
			wg.Wait()
			close(stop)
			<-done
			if name == "jail" {
				var kept testJail
				if err := c.Maps[name].LookupWithFlags(capacityAddress(0), &kept, ebpf.LookupLock); err != nil || kept.UntilNS != until || kept.Retired != 0 {
					t.Fatal("active jail evicted/revived", kept, err)
				}
			} else {
				var kept testScan
				if err := c.Maps[name].LookupWithFlags(capacityAddress(0), &kept, ebpf.LookupLock); err != nil || kept.Count != 1 || kept.Retired != 0 {
					t.Fatal("active scan evicted/revived", kept.Count, err)
				}
			}
			if c := totals(t, c); c.Passed+c.Dropped != 400 {
				t.Fatalf("inexact totals %+v", c)
			}
		})
	}
}

// Diagnostic scale is explicit. Full production capacities remain guarded by
// the existing capacity suite; this fits the supplied one-CPU/961-MiB VM.
func TestKernelNovelSourcePressureLatency(t *testing.T) {
	if os.Getenv("TC_PRESSURE_TEST") != "1" {
		t.Skip("set TC_PRESSURE_TEST=1 for repeated full-active pressure timings")
	}
	for _, name := range []string{"jail", "scans"} {
		t.Run(name, func(t *testing.T) {
			const entries = 8192
			conf := cfg(testRule{Action: jailAction, JailSeconds: 60})
			if name == "scans" {
				conf = cfg()
				conf.ScanPorts = 3
				conf.ScanWindowSeconds = 3600
				conf.ScanJailSeconds = 60
			}
			c := loadPolicySized(t, conf, nil, entries)
			now := monotonicNS(t)
			for i := 0; i < entries; i++ {
				var err error
				if name == "jail" {
					err = c.Maps[name].Put(capacityAddress(i), testJail{UntilNS: now + uint64(time.Hour)})
				} else {
					err = c.Maps[name].Put(capacityAddress(i), testScan{Generation: 1, StartNS: now, Count: 1})
				}
				if err != nil {
					t.Fatalf("fill %s offset=%d: %v", name, i, err)
				}
			}
			latencies := make([]time.Duration, 256)
			start := time.Now()
			for i := range latencies {
				frame := ipv6(fmt.Sprintf("fd01::%x", i+1), 17, udp(1))
				before := time.Now()
				runPacket(t, c, frame, drop)
				latencies[i] = time.Since(before)
			}
			elapsed := time.Since(start)
			sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
			t.Logf("%s: entries=%d full-active novel-source packets=256 elapsed=%s pps=%.0f syscall-latency p50=%s p95=%s p99=%s max=%s", name, entries, elapsed, 256/elapsed.Seconds(), latencies[128], latencies[243], latencies[253], latencies[255])
			before := time.Now()
			collectRequested(t, c)
			t.Logf("off-packet full-active sweep %s", time.Since(before))
			h, err := readHealth(c.Maps["health"])
			if err != nil {
				t.Fatal(err)
			}
			if name == "jail" && h.JailFull != 256 || name == "scans" && h.ScanFull != 256 {
				t.Fatal(h)
			}
			// An actual freed slot permits admission on the very next packet.
			if err := c.Maps[name].Delete(capacityAddress(0)); err != nil {
				t.Fatal(err)
			}
			frame := ipv6("fd01::ffff", 17, udp(1))
			want := uint32(drop)
			if name == "scans" {
				want = pass
			}
			runPacket(t, c, frame, want)
			key := addr("fd01::ffff")
			if name == "jail" {
				var v testJail
				if err := c.Maps[name].LookupWithFlags(key, &v, ebpf.LookupLock); err != nil || v.UntilNS <= now {
					t.Fatal(v, err)
				}
			} else {
				var v testScan
				if err := c.Maps[name].LookupWithFlags(key, &v, ebpf.LookupLock); err != nil || v.Count != 1 {
					t.Fatal(v.Count, err)
				}
			}
		})
	}
}
