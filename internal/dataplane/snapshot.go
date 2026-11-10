package dataplane

import (
	"errors"
	"fmt"

	"github.com/TANKominator5/BytecodeBouncer/internal/contract"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func countersFrom(m *ebpf.Map) (Counters, error) {
	var values []Counters
	if err := m.Lookup(uint32(0), &values); err != nil {
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
func (p *Plane) Counters() (Counters, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return Counters{}, fmt.Errorf("dataplane closed")
	}
	return countersFrom(p.collection.Maps["counters"])
}
func (p *Plane) ReadState() (contract.State, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return contract.State{}, fmt.Errorf("dataplane closed")
	}
	s := contract.State{Generation: p.version, Rules: []contract.RuleSample{}, Sets: []contract.SetStats{}, Sources: []contract.SourceCount{}, Jails: []contract.JailRecord{}}
	var err error
	s.Counters, err = countersFrom(p.collection.Maps["counters"])
	if err != nil {
		return s, err
	}
	s.Health, err = readHealth(p.collection.Maps["health"])
	if err != nil {
		return s, err
	}
	for i, r := range p.policy.Config.Rules[:p.policy.Config.RuleCount] {
		var values []contract.RuleCounters
		if err := p.collection.Maps["rule_counters"].Lookup(uint32(i), &values); err != nil {
			return s, err
		}
		sample := contract.RuleSample{Line: r.Line}
		for _, v := range values {
			sample.Counters.Hits += v.Hits
			sample.Counters.Passed += v.Passed
			sample.Counters.Dropped += v.Dropped
			sample.Counters.Bounced += v.Bounced
			sample.Counters.Honeypotted += v.Honeypotted
		}
		s.Rules = append(s.Rules, sample)
	}
	for _, set := range p.policy.Sets {
		s.Sets = append(s.Sets, contract.SetStats{Name: set.Name, Prefixes: uint32(len(set.Prefixes))})
	}
	// Batch reads avoid one pair of syscalls for every source at high cardinality.
	var cursor ebpf.MapBatchCursor
	keys := make([]contract.Address, 1024)
	counts := make([]uint64, 1024)
	for {
		n, err := p.collection.Maps["sources"].BatchLookup(&cursor, keys, counts, nil)
		for i := 0; i < n; i++ {
			s.Sources = append(s.Sources, contract.SourceCount{Src: keys[i], Packets: counts[i]})
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break
		}
		if err != nil {
			return s, err
		}
	}
	jail, err := readJail(p.collection.Maps["jail"])
	if err != nil {
		return s, err
	}
	s.Jails, s.NowNS = jail.Jails, jail.NowNS
	return s, nil
}

func readHealth(m *ebpf.Map) (contract.Health, error) {
	var sum contract.Health
	var health []contract.Health
	if err := m.Lookup(uint32(0), &health); err != nil {
		return contract.Health{}, err
	}
	for _, v := range health {
		sum.SourceFull += v.SourceFull
		sum.JailFull += v.JailFull
		sum.ScanFull += v.ScanFull
		sum.BucketFailed += v.BucketFailed
		sum.EventLost += v.EventLost
		sum.ConfigMissing += v.ConfigMissing
	}
	return sum, nil
}
func readJail(m *ebpf.Map) (contract.JailState, error) {
	s := contract.JailState{Jails: []contract.JailRecord{}}
	var cursor ebpf.MapBatchCursor
	keys := make([]contract.Address, 1024)
	jails := make([]contract.JailValue, 1024)
	for {
		n, err := m.BatchLookup(&cursor, keys, jails, &ebpf.BatchOptions{ElemFlags: uint64(ebpf.LookupLock)})
		for i := 0; i < n; i++ {
			if jails[i].Retired == 0 && jails[i].UntilNS > 0 {
				s.Jails = append(s.Jails, contract.JailRecord{Src: keys[i], UntilNS: jails[i].UntilNS})
			}
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break
		}
		if err != nil {
			return s, err
		}
	}
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return s, err
	}
	s.NowNS = uint64(now.Nano())
	return s, nil
}

func (p *Plane) ReadHealth() (contract.Health, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return contract.Health{}, fmt.Errorf("dataplane closed")
	}
	return readHealth(p.collection.Maps["health"])
}
func (p *Plane) ReadJail() (contract.JailState, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return contract.JailState{}, fmt.Errorf("dataplane closed")
	}
	return readJail(p.collection.Maps["jail"])
}
