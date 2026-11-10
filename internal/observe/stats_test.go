package observe

import (
	"encoding/json"
	"errors"
	"github.com/TANKominator5/BytecodeBouncer/internal/contract"
	"net/netip"
	"reflect"
	"testing"
)

type stateReader struct {
	state contract.State
	err   error
}

func (r stateReader) ReadState() (contract.State, error) { return r.state, r.err }
func TestStateSnapshot(t *testing.T) {
	state := contract.State{Generation: 7, NowNS: 100, Counters: contract.Counters{Passed: 20, Dropped: 3, Jailed: 2, DefaultHits: 4}, Rules: []contract.RuleSample{{Line: 9, Counters: contract.RuleCounters{Hits: 3, Dropped: 3}}}, Sets: []contract.SetStats{{Name: "z", Prefixes: 2}, {Name: "a", Prefixes: 1}}, Jails: []contract.JailRecord{{UntilNS: 101}, {UntilNS: 100}, {UntilNS: 99}}}
	for _, text := range []string{"2001:db8::2", "10.0.0.10", "10.0.0.2", "::ffff:10.0.0.1", "2001:db8::1", "192.0.2.1"} {
		a := netip.MustParseAddr(text)
		addr := contract.Address{Family: 6, Bytes: a.As16()}
		if a.Is4() {
			addr = contract.Address{Family: 4}
			v := a.As4()
			copy(addr.Bytes[:], v[:])
		}
		state.Sources = append(state.Sources, contract.SourceCount{Src: addr, Packets: 10})
	}
	state.Sources[0].Packets = 11
	got, err := StateSnapshot(stateReader{state: state})
	if err != nil {
		t.Fatal(err)
	}
	if got.RulesVersion != 7 || got.Passed != 20 || got.Dropped != 3 || got.Jailed != 2 || got.JailedSources != 1 || got.DefaultHits != 4 || len(got.Rules) != 1 || got.Rules[0].Line != 9 || got.Rules[0].Dropped != 3 {
		t.Fatalf("stats %+v", got)
	}
	want := []contract.SourceStats{{Src: "2001:db8::2", Packets: 11}, {Src: "10.0.0.2", Packets: 10}, {Src: "10.0.0.10", Packets: 10}, {Src: "192.0.2.1", Packets: 10}, {Src: "::ffff:10.0.0.1", Packets: 10}}
	if !reflect.DeepEqual(got.TopSources, want) {
		t.Fatalf("ranking %+v", got.TopSources)
	}
	// Map iteration order varies; the best source may arrive after five rows.
	for shift := 1; shift < len(state.Sources); shift++ {
		reordered := state
		reordered.Sources = append(append([]contract.SourceCount{}, state.Sources[shift:]...), state.Sources[:shift]...)
		ranked, err := StateSnapshot(stateReader{state: reordered})
		if err != nil || !reflect.DeepEqual(ranked.TopSources, want) {
			t.Fatalf("rotation %d: %+v %v", shift, ranked.TopSources, err)
		}
	}
	if got.Sets[0].Name != "a" || state.Sets[0].Name != "z" {
		t.Fatal("set ordering mutated input")
	}
	got.Sets[0].Name = "changed"
	got.Rules[0].Line = 1
	if state.Sets[1].Name != "a" || state.Rules[0].Line != 9 {
		t.Fatal("snapshot aliases input")
	}
}
func TestStateSnapshotEmptyAndError(t *testing.T) {
	got, err := StateSnapshot(stateReader{})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"rules", "sets", "top_sources"} {
		if string(fields[key]) != "[]" {
			t.Fatalf("%s: %s", key, fields[key])
		}
	}
	failure := errors.New("read failure")
	if _, err := StateSnapshot(stateReader{err: failure}); !errors.Is(err, failure) {
		t.Fatal(err)
	}
}
