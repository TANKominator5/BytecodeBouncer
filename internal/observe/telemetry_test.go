package observe

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/TANKominator5/BytecodeBouncer/internal/contract"
)

type fakeState struct {
	mu    sync.Mutex
	state contract.State
}

func (f *fakeState) ReadState() (contract.State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state, nil
}

type streamMessage struct {
	record contract.EventRecord
	err    error
}
type fakeStream struct {
	queue chan streamMessage
	done  chan struct{}
	once  sync.Once
}

func newFakeStream() *fakeStream {
	return &fakeStream{queue: make(chan streamMessage, 10000), done: make(chan struct{})}
}
func (f *fakeStream) ReadEvent() (contract.EventRecord, error) {
	select {
	case <-f.done:
		return contract.EventRecord{}, os.ErrClosed
	case m := <-f.queue:
		return m.record, m.err
	}
}
func (f *fakeStream) Flush() error {
	select {
	case <-f.done:
		return os.ErrClosed
	case f.queue <- streamMessage{err: contract.ErrEventsFlushed}:
		return nil
	}
}
func (f *fakeStream) Close() error { f.once.Do(func() { close(f.done) }); return nil }
func rawAddress(text string) contract.Address {
	ip := netip.MustParseAddr(text)
	r := contract.Address{Family: 6, Bytes: ip.As16()}
	if ip.Is4() {
		r = contract.Address{Family: 4}
		v := ip.As4()
		copy(r.Bytes[:], v[:])
	}
	return r
}
func TestExactSnapshotOrdering(t *testing.T) {
	state := contract.State{Generation: 7, NowNS: 1000000000, Counters: contract.Counters{Passed: 11, Dropped: 7, Bounced: 3, Honeypotted: 2, Malformed: 1, Other: 2, Jailed: 4, DefaultHits: 8}, Rules: []contract.RuleSample{{Line: 40, Counters: contract.RuleCounters{Hits: 5, Dropped: 5}}, {Line: 5, Counters: contract.RuleCounters{Hits: 6, Passed: 6}}}, Sets: []contract.SetStats{{Name: "z", Prefixes: 2}, {Name: "a", Prefixes: 0}}}
	for _, s := range []string{"2001:db8::2", "10.0.0.10", "10.0.0.2", "::1", "192.0.2.1", "10.0.0.1"} {
		state.Sources = append(state.Sources, contract.SourceCount{Src: rawAddress(s), Packets: 100})
	}
	state.Sources = append(state.Sources, contract.SourceCount{Src: rawAddress("2001:db8::2"), Packets: 101})
	state.Jails = []contract.JailRecord{{Src: rawAddress("2001:0DB8:0:0:0:0:0:1"), UntilNS: 2000000001}, {Src: rawAddress("10.0.0.10"), UntilNS: 3000000000}, {Src: rawAddress("10.0.0.2"), UntilNS: 1000000001}, {Src: rawAddress("::2"), UntilNS: 1000000000}}
	s, err := statsFrom(state)
	if err != nil {
		t.Fatal(err)
	}
	var sources []string
	for _, v := range s.TopSources {
		sources = append(sources, v.Src)
	}
	want := []string{"2001:db8::2", "10.0.0.1", "10.0.0.2", "10.0.0.10", "192.0.2.1"}
	if !reflect.DeepEqual(sources, want) || s.TopSources[0].Packets != 101 {
		t.Fatalf("top sources %+v", s.TopSources)
	}
	if s.RulesVersion != 7 || s.JailedSources != 3 || s.Rules[0].Line != 40 || s.Rules[1].Line != 5 || s.Sets[0].Name != "a" || state.Sets[0].Name != "z" {
		t.Fatalf("snapshot %+v", s)
	}
	j, err := jailFrom(state)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(j, []contract.JailEntry{{Src: "10.0.0.2", SecondsLeft: 1}, {Src: "10.0.0.10", SecondsLeft: 2}, {Src: "2001:db8::1", SecondsLeft: 2}}) {
		t.Fatal(j)
	}
	empty, err := statsFrom(contract.State{Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(empty)
	for _, field := range []string{`"rules":[]`, `"sets":[]`, `"top_sources":[]`} {
		if !strings.Contains(string(data), field) {
			t.Fatal(string(data))
		}
	}
}
func TestCanonicalAddresses(t *testing.T) {
	for _, tc := range []struct{ input, want string }{{"2001:0DB8:0:0:0:0:0:1", "2001:db8::1"}, {"::ffff:192.0.2.9", "::ffff:c000:209"}, {"0:0:0:0:0:0:0:0", "::"}, {"192.0.2.9", "192.0.2.9"}} {
		got, err := address(rawAddress(tc.input))
		if err != nil || got != tc.want {
			t.Fatalf("%s: %s %v", tc.input, got, err)
		}
	}
}

func TestEventHistoryBarrierAndCopies(t *testing.T) {
	f := newFakeStream()
	state := &fakeState{state: contract.State{Generation: 1}}
	s := New(state, f)
	defer s.Close()
	for i := 0; i < 2005; i++ {
		line := uint32(8)
		gen := uint64(1)
		if i >= 1500 {
			line = 19
			gen = 2
		}
		f.queue <- streamMessage{record: contract.EventRecord{Line: line, Generation: gen, Verdict: contract.Drop, Src: rawAddress("2001:0db8::7"), Dst: rawAddress("2001:db8::1"), Proto: 17, HasPorts: 1, Sport: 40000, Dport: uint16(i)}}
	}
	log, err := s.Log()
	if err != nil {
		t.Fatal(err)
	}
	if len(log) != 1000 || *log[0].Dport != 1005 || *log[999].Dport != 2004 || log[0].Line != 8 || log[999].Line != 19 || log[0].Src != "2001:db8::7" {
		t.Fatalf("history %d %+v %+v", len(log), log[0], log[len(log)-1])
	}
	*log[0].Dport = 7
	again, err := s.Log()
	if err != nil || *again[0].Dport != 1005 {
		t.Fatal("aliased history", err)
	}
	state.mu.Lock()
	state.state.Generation = 2
	state.mu.Unlock()
	snapshot, err := s.Stats()
	if err != nil || snapshot.RulesVersion != 2 {
		t.Fatal(snapshot, err)
	}
	if len(again) != 1000 {
		t.Fatal("reload reset history")
	}
	for _, verdict := range []uint32{contract.Pass, contract.Drop, contract.Bounce, contract.Honeypot} {
		e, err := eventFrom(contract.EventRecord{Verdict: verdict, Src: rawAddress("10.0.0.7"), Dst: rawAddress("10.0.0.1"), Proto: 99})
		if err != nil || e.Sport != nil || e.Dport != nil || e.Proto != "99" {
			t.Fatal(e, err)
		}
		b, _ := json.Marshal(e)
		if !strings.Contains(string(b), `"sport":null`) {
			t.Fatal(string(b))
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 20; n++ {
				if _, err := s.Stats(); err != nil {
					t.Error(err)
				}
				if _, err := s.Log(); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Log(); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
}
func TestEventFailureVisible(t *testing.T) {
	f := newFakeStream()
	s := New(&fakeState{}, f)
	defer s.Close()
	f.queue <- streamMessage{err: errors.New("broken event stream")}
	if _, err := s.Log(); err == nil {
		t.Fatal("stream failure hidden")
	}
	d, err := s.Diagnostics()
	if err != nil || d.StreamError == "" {
		t.Fatal(d, err)
	}
}
