package observe

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"

	"github.com/TANKominator5/BytecodeBouncer/internal/contract"
)

//go:embed web/*
var web embed.FS

func Handler(telemetry contract.Telemetry) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/stats.json", func(w http.ResponseWriter, r *http.Request) {
		v, err := telemetry.Stats()
		if err != nil {
			http.Error(w, "cannot read stats", http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode(v)
	})
	mux.HandleFunc("/jail.json", func(w http.ResponseWriter, r *http.Request) {
		v, err := telemetry.Jail()
		if err != nil {
			http.Error(w, "cannot read jail", http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode(v)
	})
	mux.HandleFunc("/log.json", func(w http.ResponseWriter, r *http.Request) {
		v, err := telemetry.Log()
		if err != nil {
			http.Error(w, "cannot read events", http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode(v)
	})
	mux.HandleFunc("/health.json", func(w http.ResponseWriter, r *http.Request) {
		provider, ok := telemetry.(interface{ Diagnostics() (Diagnostics, error) })
		if !ok {
			http.Error(w, "diagnostics unavailable", http.StatusServiceUnavailable)
			return
		}
		v, err := provider.Diagnostics()
		if err != nil {
			http.Error(w, "cannot read diagnostics", http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode(v)
	})
	files, _ := fs.Sub(web, "web")
	mux.Handle("/", http.FileServer(http.FS(files)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == "/stats.json" || r.URL.Path == "/jail.json" || r.URL.Path == "/log.json" || r.URL.Path == "/health.json" {
			w.Header().Set("Content-Type", "application/json")
		}
		mux.ServeHTTP(w, r)
	})
}
