package dataplane

import (
	"fmt"
	"time"

	"github.com/TANKominator5/BytecodeBouncer/internal/contract"
	"github.com/cilium/ebpf"
)

// At most one sweep per requested map per tick, not one sweep per failed packet.
// A productive sweep frees up to 256 slots. Failure remains diagnostic DROP until
// capacity is recovered; the daemon never implements a packet verdict or deletes
// a locked value through userspace syscalls.
const maintenanceInterval = 100 * time.Millisecond

func (p *Plane) startMaintenance() {
	p.maintenanceStop = make(chan struct{})
	p.maintenanceDone = make(chan struct{})
	go func() {
		defer close(p.maintenanceDone)
		ticker := time.NewTicker(maintenanceInterval)
		defer ticker.Stop()
		for {
			select {
			case <-p.maintenanceStop:
				return
			case <-ticker.C:
				ran, err := p.maintain()
				p.mu.Lock()
				if ran || err != nil {
					p.maintenanceErr = err
				}
				p.mu.Unlock()
			}
		}
	}()
}

func (p *Plane) maintain() (bool, error) {
	// Clone program FDs while pinning a complete generation, then release mu
	// BEFORE running a potentially full-map sweep. Reload/unjail/snapshots must
	// not wait for the sweep. Clones pin their original maps/config through RCU.
	programs, err := p.maintenancePrograms()
	if err != nil {
		return false, err
	}
	defer func() {
		for _, prog := range programs {
			prog.Close()
		}
	}()
	for _, prog := range programs {
		if _, err := prog.Run(&ebpf.RunOptions{Data: make([]byte, 14), Repeat: 1}); err != nil {
			return true, fmt.Errorf("state maintenance: %w", err)
		}
	}
	return len(programs) > 0, nil
}

func (p *Plane) maintenancePrograms() ([]*ebpf.Program, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var programs []*ebpf.Program
	if p.closed {
		return programs, nil
	}
	for i, name := range []string{"reclaim_jail_command", "reclaim_scan_command"} {
		var state uint64
		err := p.collection.Maps["maintenance"].Lookup(uint32(i), &state)
		if err == nil && state == contract.GCRequested {
			var prog *ebpf.Program
			prog, err = p.collection.Programs[name].Clone()
			if err == nil {
				programs = append(programs, prog)
			}
		}
		if err != nil {
			for _, prog := range programs {
				prog.Close()
			}
			return nil, fmt.Errorf("state maintenance: %w", err)
		}
	}
	return programs, nil
}
