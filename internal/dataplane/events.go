package dataplane

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/TANKominator5/BytecodeBouncer/internal/contract"
	"github.com/cilium/ebpf/ringbuf"
)

type eventStream struct {
	reader *ringbuf.Reader
	record ringbuf.Record // One consumer; reusable sample storage.
	once   sync.Once
	err    error
}

func (p *Plane) Events() (contract.EventReader, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, fmt.Errorf("dataplane closed")
	}
	if p.stream != nil {
		return nil, fmt.Errorf("event consumer already exists")
	}
	r, err := ringbuf.NewReader(p.collection.Maps["events"])
	if err != nil {
		return nil, err
	}
	p.stream = &eventStream{reader: r}
	return p.stream, nil
}
func (r *eventStream) ReadEvent() (contract.EventRecord, error) {
	err := r.reader.ReadInto(&r.record)
	if errors.Is(err, ringbuf.ErrFlushed) {
		return contract.EventRecord{}, contract.ErrEventsFlushed
	}
	if err != nil {
		return contract.EventRecord{}, err
	}
	var event contract.EventRecord
	if len(r.record.RawSample) != binary.Size(event) {
		return event, fmt.Errorf("invalid event record length")
	}
	err = binary.Read(bytes.NewReader(r.record.RawSample), binary.LittleEndian, &event)
	return event, err
}
func (r *eventStream) Flush() error { return r.reader.Flush() }
func (r *eventStream) Close() error { r.once.Do(func() { r.err = r.reader.Close() }); return r.err }
