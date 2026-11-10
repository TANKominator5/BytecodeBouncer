//go:build linux

package dataplane

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TANKominator5/BytecodeBouncer/internal/config"
	"github.com/TANKominator5/BytecodeBouncer/internal/contract"
	"github.com/cilium/ebpf"
)

func productionPlane(t *testing.T, input string) *Plane {
	t.Helper()
	requireBPF(t)
	policy, err := config.ParseReader(strings.NewReader(input), false)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		t.Fatal(err)
	}
	p := &Plane{spec: spec, version: 1}
	start := time.Now()
	p.collection, p.policy, err = p.prepare(policy, 1, nil)
	t.Logf("production generation preparation: %s", time.Since(start))
	if err != nil {
		t.Fatalf("prepare: %+v", err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}
func TestKernelProductionControl(t *testing.T) {
	p := productionPlane(t, "# original line\nset blocked 10.0.0.9\ndrop src @blocked log\njail 60 proto udp dport 9\nlimit 3/s burst 3 proto udp dport 10 log\n")
	r, err := p.Events()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Events(); err == nil {
		t.Fatal("accepted two ring consumers")
	}
	runPacket(t, p.collection, ipv4("10.0.0.9", 17, 0, 5, udp(1)), drop)
	if err := r.Flush(); err != nil {
		t.Fatal(err)
	}
	e, err := r.ReadEvent()
	if err != nil || e.Line != 3 || e.Verdict != contract.Drop {
		t.Fatalf("event %+v %v", e, err)
	}
	if _, err := r.ReadEvent(); !errors.Is(err, contract.ErrEventsFlushed) {
		t.Fatalf("flush barrier: %v", err)
	}
	if err := p.EditSet(false, "blocked", netip.MustParsePrefix("10.0.0.9/32")); err != nil {
		t.Fatal(err)
	}
	runPacket(t, p.collection, ipv4("10.0.0.9", 17, 0, 5, udp(1)), pass)
	if err := p.EditSet(true, "blocked", netip.MustParsePrefix("2001:db8::7/128")); err != nil {
		t.Fatal(err)
	}
	if err := p.EditSet(true, "blocked", netip.MustParsePrefix("2001:db8::7/128")); err != nil {
		t.Fatal(err)
	}
	runPacket(t, p.collection, ipv6("2001:db8::7", 17, udp(1)), drop)
	if err := p.EditSet(false, "missing", netip.MustParsePrefix("::/0")); err == nil {
		t.Fatal("unknown set")
	}
	if err := p.EditSet(false, "blocked", netip.MustParsePrefix("::/0")); err == nil {
		t.Fatal("absent prefix")
	}
	runPacket(t, p.collection, ipv6("2001:db8:1::7", 17, udp(9)), drop)
	s, err := p.ReadState()
	if err != nil {
		t.Fatal(err)
	}
	if s.Generation != 1 || s.Counters.Dropped != 3 || s.Counters.Passed != 1 || len(s.Sources) != 3 || len(s.Jails) != 1 || s.Sets[0].Prefixes != 1 || s.Rules[0].Line != 3 || s.Rules[0].Counters.Hits != 2 {
		t.Fatalf("snapshot %+v", s)
	}
	if err := p.Unjail(netip.MustParseAddr("2001:db8:1::7")); err != nil {
		t.Fatal(err)
	}
	if err := p.Unjail(netip.MustParseAddr("2001:db8:1::7")); err == nil {
		t.Fatal("released absent jail")
	}
	runPacket(t, p.collection, ipv6("2001:db8:1::7", 17, udp(1)), pass)
	for i := 0; i < 4; i++ {
		want := uint32(pass)
		if i == 3 {
			want = drop
		}
		runPacket(t, p.collection, ipv4("10.0.0.2", 17, 0, 5, udp(10)), want)
	}
	// Close must interrupt a blocked ReadEvent (drain queued records first).
	if err := r.Flush(); err != nil {
		t.Fatal(err)
	}
	for {
		_, err := r.ReadEvent()
		if errors.Is(err, contract.ErrEventsFlushed) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan error, 1)
	go func() { _, err := r.ReadEvent(); done <- err }()
	r.Close()
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("closed read: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock reader")
	}
}
