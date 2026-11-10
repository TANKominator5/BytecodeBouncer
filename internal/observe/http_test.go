package observe

import (
	"encoding/json"
	"errors"
	"github.com/TANKominator5/BytecodeBouncer/internal/contract"
	"net/http/httptest"
	"testing"
)

func TestStatsEndpoint(t *testing.T) {
	h := Handler(func() (Stats, error) {
		return Stats{Passed: 42, Rules: []contract.RuleStats{}, Sets: []contract.SetStats{}, TopSources: []contract.SourceStats{}}, nil
	})
	r := httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest("GET", "/stats.json", nil))
	var got Stats
	if err := json.Unmarshal(r.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if r.Code != 200 || got.Passed != 42 || r.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected response: %s", r.Body.String())
	}
}
func TestStatsReadFailure(t *testing.T) {
	h := Handler(func() (Stats, error) { return Stats{}, errors.New("private failure") })
	r := httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest("GET", "/stats.json", nil))
	if r.Code != 500 || r.Body.String() != "cannot read counters\n" {
		t.Fatalf("unexpected response: %d %s", r.Code, r.Body.String())
	}
}
