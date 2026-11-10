package observe

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/TANKominator5/BytecodeBouncer/internal/contract"
)

type Stats = contract.Stats

func Snapshot(p contract.CounterReader) (Stats, error) {
	c, err := p.Counters()
	if err != nil {
		return Stats{}, err
	}
	return Stats{Passed: c.Passed, Dropped: c.Dropped, Bounced: c.Bounced, Honeypotted: c.Honeypotted, Malformed: c.Malformed, Other: c.Other, Jailed: c.Jailed, DefaultHits: c.DefaultHits, RulesVersion: 1, Rules: []contract.RuleStats{}, Sets: []contract.SetStats{}, TopSources: []contract.SourceStats{}}, nil
}

// StateSnapshot uses one generation-consistent map read for CLI and HTTP.
// Snapshot remains the bootstrap CounterReader adapter for existing callers.
func StateSnapshot(reader contract.StateReader) (Stats, error) {
	state, err := reader.ReadState()
	if err != nil {
		return Stats{}, err
	}
	c := state.Counters
	result := Stats{Passed: c.Passed, Dropped: c.Dropped, Bounced: c.Bounced, Honeypotted: c.Honeypotted, Malformed: c.Malformed, Other: c.Other, Jailed: c.Jailed, DefaultHits: c.DefaultHits, RulesVersion: state.Generation, Rules: []contract.RuleStats{}, Sets: append([]contract.SetStats{}, state.Sets...), TopSources: []contract.SourceStats{}}
	for _, rule := range state.Rules {
		c := rule.Counters
		result.Rules = append(result.Rules, contract.RuleStats{Line: rule.Line, Hits: c.Hits, Passed: c.Passed, Dropped: c.Dropped, Bounced: c.Bounced, Honeypotted: c.Honeypotted})
	}
	sort.Slice(result.Sets, func(i, j int) bool { return result.Sets[i].Name < result.Sets[j].Name })
	for _, jail := range state.Jails {
		if jail.UntilNS > state.NowNS {
			result.JailedSources++
		}
	}
	type source struct {
		address netip.Addr
		packets uint64
	}
	// Keep only five candidates: O(n) time and constant extra storage even
	// when the source map is full. ReadState still materializes the map snapshot.
	sources := make([]source, 0, 5)
	for _, entry := range state.Sources {
		var address netip.Addr
		switch entry.Src.Family {
		case 4:
			address = netip.AddrFrom4([4]byte(entry.Src.Bytes[:4]))
		case 6:
			address = netip.AddrFrom16(entry.Src.Bytes)
		default:
			return Stats{}, fmt.Errorf("invalid source address family %d", entry.Src.Family)
		}

		position := 0
		for position < len(sources) {
			candidate := sources[position]
			if entry.Packets > candidate.packets || (entry.Packets == candidate.packets && address.Compare(candidate.address) < 0) {
				break
			}
			position++
		}
		if position == 5 {
			continue
		}
		if len(sources) < 5 {
			sources = append(sources, source{})
		}
		copy(sources[position+1:], sources[position:len(sources)-1])
		sources[position] = source{address, entry.Packets}
	}
	for _, entry := range sources {
		result.TopSources = append(result.TopSources, contract.SourceStats{Src: entry.address.String(), Packets: entry.packets})
	}
	return result, nil
}
