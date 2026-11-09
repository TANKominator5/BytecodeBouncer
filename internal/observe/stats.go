package observe

import "github.com/TANKominator5/BytecodeBouncer/internal/dataplane"

type Stats struct {
	Passed        uint64 `json:"passed"`
	Dropped       uint64 `json:"dropped"`
	Bounced       uint64 `json:"bounced"`
	Honeypotted   uint64 `json:"honeypotted"`
	Malformed     uint64 `json:"malformed"`
	Other         uint64 `json:"other"`
	Jailed        uint64 `json:"jailed"`
	JailedSources uint64 `json:"jailed_sources"`
	RulesVersion  uint64 `json:"rules_version"`
	DefaultHits   uint64 `json:"default_hits"`
	Rules         []any  `json:"rules"`
	Sets          []any  `json:"sets"`
	TopSources    []any  `json:"top_sources"`
}

func Snapshot(p *dataplane.Plane) (Stats, error) {
	c, err := p.Counters()
	if err != nil {
		return Stats{}, err
	}
	return Stats{Passed: c.Passed, Dropped: c.Dropped, Bounced: c.Bounced, Honeypotted: c.Honeypotted, Malformed: c.Malformed, Other: c.Other, Jailed: c.Jailed, DefaultHits: c.DefaultHits, RulesVersion: 1, Rules: []any{}, Sets: []any{}, TopSources: []any{}}, nil
}
