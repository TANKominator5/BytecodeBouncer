package daemon

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
)

func TestResponseFraming(t *testing.T) {
	for _, data := range []json.RawMessage{nil, json.RawMessage(`[]`), json.RawMessage(`[{"src":"::1","seconds_left":1}]`), json.RawMessage(`"` + strings.Repeat("x", 65536) + `"`)} {
		var wire bytes.Buffer
		if err := writeResponse(&wire, Response{Data: data}); err != nil {
			t.Fatal(err)
		}
		got, err := readResponse(&wire)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("round trip %d bytes: %v", len(data), err)
		}
	}
	var wire bytes.Buffer
	if err := writeResponse(&wire, Response{Data: json.RawMessage(`[]`), Error: "bad policy"}); err != nil {
		t.Fatal(err)
	}
	if data, err := readResponse(&wire); err == nil || err.Error() != "bad policy" || data != nil {
		t.Fatal(data, err)
	}
	for _, bad := range []string{"", "{}\n", "not json\n", "{\"version\":1,\"length\":-1}\n", "{\"version\":1,\"length\":134217729}\n", "{\"version\":1,\"length\":1,\"error\":\"bad\"}\n", "{\"version\":1,\"length\":10}\n[]", strings.Repeat("x", 8192)} {
		if _, err := readResponse(strings.NewReader(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestResponseShortWriter(t *testing.T) {
	if err := writeResponse(shortWriter{}, Response{Data: json.RawMessage(`[]`)}); err == nil {
		t.Fatal("ignored short payload write")
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) {
	if len(p) > 2 {
		return len(p), nil
	}
	return 0, io.ErrShortWrite
}

func BenchmarkResponseSocket(b *testing.B) {
	data := json.RawMessage(`[` + strings.Repeat(`{"src":"2001:db8::ffff","seconds_left":3600},`, (1<<20)-1) + `{"src":"2001:db8::ffff","seconds_left":3600}]`)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a, z := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- writeResponse(a, Response{Data: data}); a.Close() }()
		got, err := readResponse(z)
		z.Close()
		if err != nil {
			b.Fatal(err)
		}
		if err := <-done; err != nil {
			b.Fatal(err)
		}
		if !bytes.Equal(got, data) {
			b.Fatal("changed payload")
		}
	}
}

func BenchmarkResponseEnvelope(b *testing.B) {
	data := json.RawMessage(`[` + strings.Repeat(`{"src":"2001:db8::ffff","seconds_left":3600},`, (1<<20)-1) + `{"src":"2001:db8::ffff","seconds_left":3600}]`)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := json.NewEncoder(io.Discard).Encode(Response{Data: data}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkResponseFramed(b *testing.B) {
	data := json.RawMessage(`[` + strings.Repeat(`{"src":"2001:db8::ffff","seconds_left":3600},`, (1<<20)-1) + `{"src":"2001:db8::ffff","seconds_left":3600}]`)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := writeResponse(io.Discard, Response{Data: data}); err != nil {
			b.Fatal(err)
		}
	}
}
