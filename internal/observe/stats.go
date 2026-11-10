package observe

import "github.com/TANKominator5/BytecodeBouncer/internal/contract"

type Stats = contract.Stats

func Snapshot(p contract.CounterReader) (Stats, error) {
	c, err := p.Counters()
	if err != nil {
		return Stats{}, err
	}
	return Stats{Passed: c.Passed, Dropped: c.Dropped, Bounced: c.Bounced, Honeypotted: c.Honeypotted, Malformed: c.Malformed, Other: c.Other, Jailed: c.Jailed, DefaultHits: c.DefaultHits, RulesVersion: 1, Rules: []contract.RuleStats{}, Sets: []contract.SetStats{}, TopSources: []contract.SourceStats{}}, nil
}
