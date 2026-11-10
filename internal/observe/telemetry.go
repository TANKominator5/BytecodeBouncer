package observe

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/TANKominator5/BytecodeBouncer/internal/contract"
)

const historySize = 1000

type Service struct {
	reader      contract.StateReader
	stream      contract.EventReader
	mu          sync.Mutex
	flushMu     sync.Mutex
	closed      bool
	streamError error
	wait        chan struct{}
	history     [historySize]contract.Event
	count, next int
	eventsRead  uint64
	done        chan struct{}
	closeOnce   sync.Once
	closeErr    error
}

var _ contract.Telemetry = (*Service)(nil)

func New(reader contract.StateReader, stream contract.EventReader) *Service {
	s := &Service{reader: reader, stream: stream, done: make(chan struct{})}
	go s.drain()
	return s
}
func eventFrom(r contract.EventRecord) (contract.Event, error) {
	e := contract.Event{Line: r.Line}
	var err error
	e.Src, err = address(r.Src)
	if err != nil {
		return e, err
	}
	e.Dst, err = address(r.Dst)
	if err != nil {
		return e, err
	}
	switch r.Verdict {
	case contract.Pass:
		e.Verdict = "PASS"
	case contract.Drop:
		e.Verdict = "DROP"
	case contract.Bounce:
		e.Verdict = "BOUNCE"
	case contract.Honeypot:
		e.Verdict = "HONEYPOT"
	default:
		return e, fmt.Errorf("invalid event verdict %d", r.Verdict)
	}
	switch r.Proto {
	case 17:
		e.Proto = "udp"
	case 6:
		e.Proto = "tcp"
	case 1:
		e.Proto = "icmp"
	case 58:
		e.Proto = "icmp6"
	default:
		e.Proto = strconv.Itoa(int(r.Proto))
	}
	if r.HasPorts != 0 {
		sport, dport := r.Sport, r.Dport
		e.Sport = &sport
		e.Dport = &dport
	}
	return e, nil
}
func (s *Service) drain() {
	defer close(s.done)
	for {
		r, err := s.stream.ReadEvent()
		if errors.Is(err, contract.ErrEventsFlushed) {
			s.mu.Lock()
			if s.wait != nil {
				close(s.wait)
				s.wait = nil
			}
			s.mu.Unlock()
			continue
		}
		if err != nil {
			s.mu.Lock()
			if !s.closed || !errors.Is(err, os.ErrClosed) {
				s.streamError = err
			}
			if s.wait != nil {
				close(s.wait)
				s.wait = nil
			}
			s.mu.Unlock()
			return
		}
		e, err := eventFrom(r)
		s.mu.Lock()
		if err != nil {
			s.streamError = err
		} else {
			s.eventsRead++
			s.history[s.next] = e
			s.next = (s.next + 1) % historySize
			if s.count < historySize {
				s.count++
			}
		}
		s.mu.Unlock()
	}
}
func (s *Service) available() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return os.ErrClosed
	}
	return nil
}
func (s *Service) Stats() (Stats, error) {
	if err := s.available(); err != nil {
		return Stats{}, err
	}
	return Snapshot(s.reader)
}
func (s *Service) Jail() ([]contract.JailEntry, error) {
	if err := s.available(); err != nil {
		return nil, err
	}
	state, err := s.reader.ReadState()
	if err != nil {
		return nil, err
	}
	return jailFrom(state)
}
func copyEvent(e contract.Event) contract.Event {
	if e.Sport != nil {
		v := *e.Sport
		e.Sport = &v
	}
	if e.Dport != nil {
		v := *e.Dport
		e.Dport = &v
	}
	return e
}
func (s *Service) Log() ([]contract.Event, error) {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()
	timer := time.NewTimer(700 * time.Millisecond)
	defer timer.Stop()
	// A timed-out request leaves its barrier outstanding. Retire it before
	// issuing another flush, so a late acknowledgment cannot satisfy a newer
	// request whose events have not yet been drained.
	s.mu.Lock()
	pending := s.wait
	s.mu.Unlock()
	if pending != nil {
		select {
		case <-pending:
		case <-timer.C:
			return nil, fmt.Errorf("event drain barrier timed out")
		}
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, os.ErrClosed
	}
	if s.streamError != nil {
		err := s.streamError
		s.mu.Unlock()
		return nil, err
	}
	wait := make(chan struct{})
	s.wait = wait
	s.mu.Unlock()
	if err := s.stream.Flush(); err != nil {
		s.mu.Lock()
		if s.wait == wait {
			s.wait = nil
		}
		s.streamError = err
		s.mu.Unlock()
		return nil, err
	}
	select {
	case <-wait:
	case <-timer.C:
		// This request timed out, but the stream may still be healthy. Keep
		// s.wait until the drain acknowledges it; terminal read errors are
		// recorded by drain and remain visible to subsequent calls.
		return nil, fmt.Errorf("event drain barrier timed out")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, os.ErrClosed
	}
	if s.streamError != nil {
		return nil, s.streamError
	}
	result := make([]contract.Event, 0, s.count)
	start := (s.next - s.count + historySize) % historySize
	for i := 0; i < s.count; i++ {
		result = append(result, copyEvent(s.history[(start+i)%historySize]))
	}
	return result, nil
}
func (s *Service) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		s.closeErr = s.stream.Close()
		<-s.done
		s.mu.Lock()
		s.history = [historySize]contract.Event{}
		s.count = 0
		s.next = 0
		s.mu.Unlock()
	})
	return s.closeErr
}

// Diagnostics is intentionally separate from the exact required stats schema.
type Diagnostics struct {
	EventsRead    uint64 `json:"events_read"`
	SourceFull    uint64 `json:"source_full"`
	JailFull      uint64 `json:"jail_full"`
	ScanFull      uint64 `json:"scan_full"`
	BucketFailed  uint64 `json:"bucket_failed"`
	EventLost     uint64 `json:"event_lost"`
	ConfigMissing uint64 `json:"config_missing"`
	StreamError   string `json:"stream_error"`
}

func (s *Service) Diagnostics() (Diagnostics, error) {
	if err := s.available(); err != nil {
		return Diagnostics{}, err
	}
	state, err := s.reader.ReadState()
	if err != nil {
		return Diagnostics{}, err
	}
	h := state.Health
	d := Diagnostics{SourceFull: h.SourceFull, JailFull: h.JailFull, ScanFull: h.ScanFull, BucketFailed: h.BucketFailed, EventLost: h.EventLost, ConfigMissing: h.ConfigMissing}
	s.mu.Lock()
	d.EventsRead = s.eventsRead
	if s.streamError != nil {
		d.StreamError = s.streamError.Error()
	}
	s.mu.Unlock()
	return d, nil
}
