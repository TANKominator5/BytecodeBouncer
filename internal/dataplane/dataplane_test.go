package dataplane

import (
	"bytes"
	"encoding/binary"
	"github.com/cilium/ebpf"
	"testing"
)

func TestObjectContract(t *testing.T) {
	s, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		t.Fatal(err)
	}
	if s.Programs["trafficcop"] == nil {
		t.Fatal("entry point missing")
	}
	m := s.Maps["counters"]
	if m == nil {
		t.Fatal("counter map missing")
	}
	if m.ValueSize != uint32(binary.Size(Counters{})) || m.Type != ebpf.PerCPUArray || m.MaxEntries != 1 {
		t.Fatalf("counter ABI mismatch: %+v", m)
	}
}
