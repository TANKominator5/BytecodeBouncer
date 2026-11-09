package observe

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
)

//go:embed web/*
var web embed.FS

func Handler(snapshot func() (Stats, error)) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/stats.json", func(w http.ResponseWriter, r *http.Request) {
		s, err := snapshot()
		if err != nil {
			http.Error(w, "cannot read counters", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(s)
	})
	files, _ := fs.Sub(web, "web")
	mux.Handle("/", http.FileServer(http.FS(files)))
	return mux
}
