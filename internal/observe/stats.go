package observe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"

	"github.com/TANKominator5/BytecodeBouncer/internal/contract"
)

type Stats = contract.Stats

func address(a contract.Address) (string, error) {
	switch a.Family {
	case 4:
		var v [4]byte
		copy(v[:], a.Bytes[:4])
		return netip.AddrFrom4(v).String(), nil
	case 6:
		ip := netip.AddrFrom16(a.Bytes)
		// netip.String chooses dotted-decimal tails for mapped IPv6. Keep the
		// full IPv6 identity in shortest hexadecimal form, never unmap to IPv4.
		if ip.Is4In6() {
			return fmt.Sprintf("::ffff:%x:%x", binary.BigEndian.Uint16(a.Bytes[12:14]), binary.BigEndian.Uint16(a.Bytes[14:16])), nil
		}
		return ip.String(), nil
	default:
		return "", fmt.Errorf("invalid address family %d", a.Family)
	}
}
func compareAddress(a, b contract.Address) int {
	if a.Family < b.Family {
		return -1
	}
	if a.Family > b.Family {
		return 1
	}
	return bytes.Compare(a.Bytes[:], b.Bytes[:])
}
func better(a, b contract.SourceCount) bool {
	return a.Packets > b.Packets || a.Packets == b.Packets && compareAddress(a.Src, b.Src) < 0
}
func jailFrom(state contract.State) ([]contract.JailEntry, error) {
	active := make(map[contract.Address]uint64)
	for _, j := range state.Jails {
		if j.UntilNS > state.NowNS && j.UntilNS > active[j.Src] {
			active[j.Src] = j.UntilNS
		}
	}
	keys := make([]contract.Address, 0, len(active))
	for key := range active {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return compareAddress(keys[i], keys[j]) < 0 })
	result := make([]contract.JailEntry, 0, len(keys))
	for _, key := range keys {
		src, err := address(key)
		if err != nil {
			return nil, err
		}
		delta := active[key] - state.NowNS
		seconds := delta / 1000000000
		if delta%1000000000 != 0 {
			seconds++
		}
		result = append(result, contract.JailEntry{Src: src, SecondsLeft: seconds})
	}
	return result, nil
}
func Snapshot(reader contract.StateReader) (Stats, error) {
	state, err := reader.ReadState()
	if err != nil {
		return Stats{}, err
	}
	return statsFrom(state)
}
func statsFrom(state contract.State) (Stats, error) {
	c := state.Counters
	s := Stats{Passed: c.Passed, Dropped: c.Dropped, Bounced: c.Bounced, Honeypotted: c.Honeypotted, Malformed: c.Malformed, Other: c.Other, Jailed: c.Jailed, DefaultHits: c.DefaultHits, RulesVersion: state.Generation, Rules: []contract.RuleStats{}, Sets: append([]contract.SetStats{}, state.Sets...), TopSources: []contract.SourceStats{}}
	for _, r := range state.Rules {
		v := r.Counters
		s.Rules = append(s.Rules, contract.RuleStats{Line: r.Line, Hits: v.Hits, Passed: v.Passed, Dropped: v.Dropped, Bounced: v.Bounced, Honeypotted: v.Honeypotted})
	}
	sort.Slice(s.Sets, func(i, j int) bool { return s.Sets[i].Name < s.Sets[j].Name })
	// Only five candidates are retained: exact O(5*N), no full-source sort or
	// string allocation for the potentially million-entry source map.
	top := make([]contract.SourceCount, 0, 5)
	for _, src := range state.Sources {
		if src.Packets == 0 {
			continue
		}
		duplicate := -1
		for i, v := range top {
			if v.Src == src.Src {
				duplicate = i
				break
			}
		}
		if duplicate >= 0 {
			if src.Packets > top[duplicate].Packets {
				top[duplicate] = src
				sort.Slice(top, func(i, j int) bool { return better(top[i], top[j]) })
			}
			continue
		}
		at := 0
		for at < len(top) && !better(src, top[at]) {
			at++
		}
		if at >= 5 {
			continue
		}
		if len(top) < 5 {
			top = append(top, contract.SourceCount{})
		}
		copy(top[at+1:], top[at:len(top)-1])
		top[at] = src
	}
	for _, src := range top {
		text, err := address(src.Src)
		if err != nil {
			return Stats{}, err
		}
		s.TopSources = append(s.TopSources, contract.SourceStats{Src: text, Packets: src.Packets})
	}
	jail, err := jailFrom(state)
	if err != nil {
		return Stats{}, err
	}
	s.JailedSources = uint64(len(jail))
	return s, nil
}
