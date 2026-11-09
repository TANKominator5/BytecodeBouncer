// Package dataplane owns the XDP attachment and its maps.
package dataplane

import (
	"bytes"
	_ "embed"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"net"
	"sync"
)

//go:embed trafficcop.bpf.o
var object []byte

// Counters must match include/contract.h; fields are native-endian uint64.
type Counters struct{ Passed, Dropped, Bounced, Honeypotted, Malformed, Other, Jailed, DefaultHits uint64 }
type Plane struct {
	mu         sync.RWMutex
	closed     bool
	collection *ebpf.Collection
	attachment link.Link
}

func Attach(ifname string) (*Plane, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	if err = rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, err
	}
	c, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load XDP: %w", err)
	}
	l, err := link.AttachXDP(link.XDPOptions{Program: c.Programs["trafficcop"], Interface: iface.Index, Flags: link.XDPDriverMode})
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("attach native XDP: %w", err)
	}
	return &Plane{collection: c, attachment: l}, nil
}
func (p *Plane) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	err := p.attachment.Close()
	p.collection.Close()
	return err
}
func (p *Plane) Counters() (Counters, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return Counters{}, fmt.Errorf("dataplane closed")
	}
	var values []Counters
	if err := p.collection.Maps["counters"].Lookup(uint32(0), &values); err != nil {
		return Counters{}, err
	}
	var sum Counters
	for _, v := range values {
		sum.Passed += v.Passed
		sum.Dropped += v.Dropped
		sum.Bounced += v.Bounced
		sum.Honeypotted += v.Honeypotted
		sum.Malformed += v.Malformed
		sum.Other += v.Other
		sum.Jailed += v.Jailed
		sum.DefaultHits += v.DefaultHits
	}
	return sum, nil
}
