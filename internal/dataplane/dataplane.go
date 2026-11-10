// Package dataplane owns complete policy generations, maps and the XDP link.
package dataplane

import (
	"bytes"
	_ "embed"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/TANKominator5/BytecodeBouncer/internal/config"
	"github.com/TANKominator5/BytecodeBouncer/internal/contract"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:embed trafficcop.bpf.o
var object []byte

type Counters = contract.Counters

var _ contract.CounterReader = (*Plane)(nil)
var _ contract.StateReader = (*Plane)(nil)

type Plane struct {
	change     sync.Mutex   // Serializes prepare/publish, live edits, unjail and stop.
	mu         sync.RWMutex // A snapshot pins one complete generation until it finishes.
	closed     bool
	collection *ebpf.Collection
	attachment link.Link
	spec       *ebpf.CollectionSpec
	policy     *config.Policy
	version    uint64
	honeypot   uint32
	stream     *eventStream
}

// Attach preserves the bootstrap entry point for existing callers/tests.
func Attach(ifname string) (*Plane, error) {
	p, err := config.ParseReader(bytes.NewReader(nil), false)
	if err != nil {
		return nil, err
	}
	return AttachPolicy(ifname, "", p)
}
func AttachPolicy(ifname, hpname string, policy *config.Policy) (*Plane, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	var hp uint32
	if hpname != "" {
		h, err := net.InterfaceByName(hpname)
		if err != nil {
			return nil, err
		}
		hp = uint32(h.Index)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, err
	}
	p := &Plane{spec: spec, version: 1, honeypot: hp}
	c, owned, err := p.prepare(policy, 1, nil)
	if err != nil {
		return nil, err
	}
	l, err := link.AttachXDP(link.XDPOptions{Program: c.Programs["trafficcop"], Interface: iface.Index, Flags: link.XDPDriverMode})
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("attach native XDP: %w", err)
	}
	p.collection = c
	p.attachment = l
	p.policy = owned
	return p, nil
}
func clonePolicy(p *config.Policy) *config.Policy {
	r := &config.Policy{Config: p.Config, Sets: make([]config.Set, len(p.Sets))}
	for i, s := range p.Sets {
		r.Sets[i] = config.Set{Name: s.Name, ID: s.ID, Prefixes: make(map[netip.Prefix]struct{}, len(s.Prefixes))}
		for prefix := range s.Prefixes {
			r.Sets[i].Prefixes[prefix] = struct{}{}
		}
	}
	return r
}
func (p *Plane) prepare(policy *config.Policy, version uint64, shared map[string]*ebpf.Map) (_ *ebpf.Collection, _ *config.Policy, err error) {
	if policy == nil || policy.Config.RuleCount > contract.MaxRules {
		return nil, nil, fmt.Errorf("invalid policy")
	}
	owned := clonePolicy(policy)
	cfg := owned.Config
	cfg.Generation = version
	cfg.HoneypotIfindex = p.honeypot
	for _, r := range cfg.Rules[:cfg.RuleCount] {
		if r.Action == contract.Honeypot && p.honeypot == 0 {
			return nil, nil, fmt.Errorf("line %d: honeypot rule requires an interface", r.Line)
		}
	}
	owned.Config = cfg
	spec := p.spec.Copy()
	// A callback's variable rule index hides individual frozen config fields
	// from older verifiers. Explicit read-only feature unions let them prune
	// paths absent from this generation without changing first-match semantics.
	var actions, matches uint32
	for _, r := range cfg.Rules[:cfg.RuleCount] {
		actions |= 1 << r.Action
		matches |= r.Matches
	}
	if err := spec.RewriteConstants(map[string]interface{}{"enabled_actions": actions, "enabled_matches": matches}); err != nil {
		return nil, nil, err
	}
	spec.Maps["config"].Contents = []ebpf.MapKV{{Key: uint32(0), Value: cfg}}
	// Freeze BEFORE program verification and forbid program-side config writes.
	// The verifier can then prune disabled features/constant policy fields as
	// well as enforcing the immutable-generation publication contract.
	spec.Maps["config"].Flags |= unix.BPF_F_RDONLY_PROG
	configMap, err := ebpf.NewMap(spec.Maps["config"])
	if err != nil {
		return nil, nil, err
	}
	defer configMap.Close()
	if err := configMap.Freeze(); err != nil {
		return nil, nil, err
	}
	replacements := make(map[string]*ebpf.Map, len(shared)+1)
	for name, m := range shared {
		replacements[name] = m
	}
	replacements["config"] = configMap
	for _, set := range owned.Sets {
		for prefix := range set.Prefixes {
			spec.Maps["sets"].Contents = append(spec.Maps["sets"].Contents, ebpf.MapKV{Key: config.SetKey(set.ID, prefix), Value: uint32(1)})
		}
	}
	c, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: replacements})
	if err != nil {
		return nil, nil, fmt.Errorf("load XDP: %w", err)
	}
	defer func() {
		if err != nil {
			c.Close()
		}
	}()
	var keys, fds []uint32
	for i, r := range cfg.Rules[:cfg.RuleCount] {
		if r.Action == contract.Limit {
			keys = append(keys, uint32(i))
		}
	}
	inner := make([]*ebpf.Map, len(keys))
	defer func() {
		for i, m := range inner {
			if i > 0 && m != nil {
				m.Close()
			}
		}
	}()
	if len(keys) > 0 {
		inner[0] = c.Maps["bucket_template"]
		// Independent LRU maps are memory-heavy. Allocate private candidates on
		// at most four workers, never parallelize mutation/publication itself.
		jobs := make(chan int, len(keys))
		for i := 1; i < len(keys); i++ {
			jobs <- i
		}
		close(jobs)
		failures := make([]error, len(keys))
		var workers sync.WaitGroup
		for worker := 0; worker < 4; worker++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for i := range jobs {
					inner[i], failures[i] = ebpf.NewMap(spec.Maps["buckets"].InnerMap.Copy())
				}
			}()
		}
		workers.Wait()
		for i, m := range inner {
			if failures[i] != nil {
				return nil, nil, failures[i]
			}
			fds = append(fds, uint32(m.FD()))
		}
	}
	if len(keys) > 0 {
		if _, err = c.Maps["buckets"].BatchUpdate(keys, fds, nil); err != nil {
			return nil, nil, err
		}
	}
	return c, owned, nil
}
func (p *Plane) Reload(policy *config.Policy) error {
	p.change.Lock()
	defer p.change.Unlock()
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return fmt.Errorf("dataplane closed")
	}
	shared := make(map[string]*ebpf.Map)
	for _, name := range []string{"counters", "health", "maintenance", "sources", "jail", "events"} {
		shared[name] = p.collection.Maps[name]
	}
	version := p.version + 1
	p.mu.RUnlock()
	// Candidate preparation never mutates the active config, sets or counters.
	next, owned, err := p.prepare(policy, version, shared)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.attachment.Update(next.Programs["trafficcop"]); err != nil {
		next.Close()
		return fmt.Errorf("publish XDP policy: %w", err)
	}
	old := p.collection
	p.collection = next
	p.policy = owned
	p.version = version
	// Kernel program/map references and RCU protect in-flight old invocations.
	old.Close()
	return nil
}
func (p *Plane) HasHoneypot() bool { return p.honeypot != 0 }
func (p *Plane) EditSet(add bool, name string, prefix netip.Prefix) error {
	if !prefix.IsValid() {
		return fmt.Errorf("invalid prefix")
	}
	p.change.Lock()
	defer p.change.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return fmt.Errorf("dataplane closed")
	}
	prefix = prefix.Masked()
	total := 0
	for _, s := range p.policy.Sets {
		total += len(s.Prefixes)
	}
	for i := range p.policy.Sets {
		s := &p.policy.Sets[i]
		if s.Name != name {
			continue
		}
		_, exists := s.Prefixes[prefix]
		if add && exists {
			return nil
		}
		if !add && !exists {
			return fmt.Errorf("prefix is not in set %q", name)
		}
		key := config.SetKey(s.ID, prefix)
		if add {
			if total >= contract.MaxPrefixes {
				return fmt.Errorf("too many prefixes")
			}
			if err := p.collection.Maps["sets"].Put(key, uint32(1)); err != nil {
				return err
			}
			s.Prefixes[prefix] = struct{}{}
		} else {
			if err := p.collection.Maps["sets"].Delete(key); err != nil {
				return err
			}
			delete(s.Prefixes, prefix)
		}
		return nil
	}
	return fmt.Errorf("unknown set %q", name)
}
func (p *Plane) Unjail(address netip.Addr) error {
	if !address.IsValid() || address.Zone() != "" {
		return fmt.Errorf("invalid jail address")
	}
	p.change.Lock()
	defer p.change.Unlock()
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return fmt.Errorf("dataplane closed")
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		r := contract.UnjailRequest{Src: config.Address(address)}
		if err := p.collection.Maps["unjail_request"].Put(uint32(0), r); err != nil {
			return err
		}
		if _, err := p.collection.Programs["unjail_command"].Run(&ebpf.RunOptions{Data: make([]byte, 14), Repeat: 1}); err != nil {
			return err
		}
		if err := p.collection.Maps["unjail_request"].Lookup(uint32(0), &r); err != nil {
			return err
		}
		switch r.Result {
		case contract.UnjailOK:
			return nil
		case contract.UnjailAbsent:
			return fmt.Errorf("address is not jailed")
		case contract.UnjailRetry:
			if time.Now().Before(deadline) {
				continue
			}
		}
		return fmt.Errorf("cannot release address during state reclamation")
	}
}
func (p *Plane) Close() error {
	p.change.Lock()
	defer p.change.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	if p.stream != nil {
		p.stream.Close()
	}
	var err error
	if p.attachment != nil {
		err = p.attachment.Close()
	}
	p.collection.Close()
	return err
}
