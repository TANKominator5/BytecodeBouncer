package observe

import (
	"encoding/binary"
	"encoding/json"
	"math/rand"
	"reflect"
	"slices"
	"testing"

	"github.com/TANKominator5/BytecodeBouncer/internal/contract"
)

func denseJails(n int) contract.JailState {
	s := contract.JailState{NowNS: 1, Jails: make([]contract.JailRecord, n)}
	for i := range s.Jails {
		j := &s.Jails[i]
		j.Src.Family = 6
		j.Src.Bytes[0] = 0xfd
		binary.BigEndian.PutUint64(j.Src.Bytes[8:], uint64(i+1))
		j.UntilNS = 3600000000001
	}
	rand.New(rand.NewSource(1)).Shuffle(n, func(i, j int) { s.Jails[i], s.Jails[j] = s.Jails[j], s.Jails[i] })
	return s
}

func TestRadixJailOrdering(t *testing.T) {
	s := denseJails(10000)
	r := rand.New(rand.NewSource(2))
	for i := range s.Jails {
		r.Read(s.Jails[i].Src.Bytes[:])
		if i%3 == 0 {
			s.Jails[i].Src.Family = 4
		}
	}
	s.Jails = append(s.Jails, s.Jails[:100]...)
	want := append([]contract.JailRecord(nil), s.Jails...)
	slices.SortStableFunc(want, func(a, b contract.JailRecord) int { return compareAddress(a.Src, b.Src) })
	orderJails(s.Jails)
	if !reflect.DeepEqual(s.Jails, want) {
		t.Fatal("radix disagrees with numeric stable ordering")
	}
}

func BenchmarkFullJailFormat(b *testing.B) {
	s := denseJails(1 << 20)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := jailFrom(s); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFullJailMarshal(b *testing.B) {
	j, err := jailFrom(denseJails(1 << 20))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := json.Marshal(j); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFullJailStats(b *testing.B) {
	j := denseJails(1 << 20)
	s := contract.State{NowNS: j.NowNS, Jails: j.Jails}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := statsFrom(s); err != nil {
			b.Fatal(err)
		}
	}
}
