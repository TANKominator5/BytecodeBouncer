package observe

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TANKominator5/BytecodeBouncer/internal/contract"
)

type httpTelemetry struct{ fail bool }

func (f httpTelemetry) Stats() (Stats, error) {
	if f.fail {
		return Stats{}, errors.New("private failure")
	}
	return Stats{Passed: 42, Rules: []contract.RuleStats{}, Sets: []contract.SetStats{}, TopSources: []contract.SourceStats{}}, nil
}
func (f httpTelemetry) Jail() ([]contract.JailEntry, error) { return []contract.JailEntry{}, nil }
func (f httpTelemetry) Log() ([]contract.Event, error)      { return []contract.Event{}, nil }
func (f httpTelemetry) Diagnostics() (Diagnostics, error)   { return Diagnostics{}, nil }

func TestTelemetryHTTP(t *testing.T) {
	h := Handler(httpTelemetry{})
	for _, path := range []string{"/stats.json", "/jail.json", "/log.json", "/health.json"} {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest("GET", path, nil))
		if r.Code != 200 || r.Header().Get("Cache-Control") != "no-store" || r.Header().Get("Content-Type") != "application/json" || !json.Valid(r.Body.Bytes()) {
			t.Fatalf("%s: %d %s", path, r.Code, r.Body.String())
		}
		if path == "/stats.json" {
			var got Stats
			if err := json.Unmarshal(r.Body.Bytes(), &got); err != nil || got.Passed != 42 {
				t.Fatal(got, err)
			}
		}
	}
	r := httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest("POST", "/stats.json", nil))
	if r.Code != 405 || r.Header().Get("Allow") != "GET, HEAD" {
		t.Fatal(r.Code)
	}
	r = httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest("GET", "/", nil))
	if r.Code != 200 || !strings.Contains(r.Body.String(), "TIMEOUT CORNER") || r.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("dashboard/security headers")
	}
	for _, path := range []string{"/app.js", "/app.css"} {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest("GET", path, nil))
		if r.Code != 200 {
			t.Fatal(path, r.Code)
		}
	}
}
func TestStatsReadFailure(t *testing.T) {
	r := httptest.NewRecorder()
	Handler(httpTelemetry{fail: true}).ServeHTTP(r, httptest.NewRequest("GET", "/stats.json", nil))
	if r.Code != 503 || r.Body.String() != "cannot read stats\n" {
		t.Fatalf("unexpected response: %d %s", r.Code, r.Body.String())
	}
}
