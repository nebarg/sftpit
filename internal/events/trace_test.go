package events_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/events"
)

func TestTraceWritesEachEventAsALine(t *testing.T) {
	var w traceWriter
	r := events.NewRecorder(time.Now(), 2, events.NewTrace(&w, 1<<20))
	for i := range 3 {
		r.Record(events.Event{Kind: events.Connected, Connection: uint64(i + 1)})
	}
	lines := traceLines(t, w.Bytes())
	if got := kindsAndIDs(lines); !slices.Equal(got, []string{"connected 1", "connected 2", "connected 3"}) {
		t.Errorf("the trace holds %v, want all three events, though the recorder keeps two", got)
	}
	if lines[0].Time.IsZero() || lines[2].Connection != 3 {
		t.Errorf("the trace's events are %+v, want them timed and whole", lines)
	}
	if s := r.Trace(); s.Size != int64(w.Len()) || !s.Complete || s.Err != nil {
		t.Errorf("trace status = %+v, want %d bytes, complete", s, w.Len())
	}
	r.Close()
	if !w.closed {
		t.Error("closing the recorder left the trace open")
	}
}

func TestTraceStopsAtItsLimitAndSaysSo(t *testing.T) {
	var w traceWriter
	// Room for two lines and part of a third, whose times and durations
	// vary in length by a few bytes.
	typical := len(line(t, events.Event{ID: 1, Time: time.Now().UTC(), Elapsed: events.Millis(time.Millisecond), Kind: events.Connected, Connection: 1}))
	limit := int64(typical * 5 / 2)
	r := events.NewRecorder(time.Now(), 10, events.NewTrace(&w, limit))
	for i := range 4 {
		r.Record(events.Event{Kind: events.Connected, Connection: uint64(i + 1)})
	}
	lines := traceLines(t, w.Bytes())
	if got := kindsAndIDs(lines); !slices.Equal(got, []string{"connected 1", "connected 2", "trace_full 3"}) {
		t.Errorf("the trace holds %v, want two events and then trace_full at the first left out", got)
	}
	if s := r.Trace(); s.Complete || s.Err != nil || s.Size != int64(w.Len()) {
		t.Errorf("trace status = %+v, want incomplete, without an error, at %d bytes", s, w.Len())
	}
	if got := len(r.Events(0, 10, events.Filter{}).Events); got != 4 {
		t.Errorf("the recorder keeps %d events, want all 4, without trace_full", got)
	}
}

func TestTraceStopsAtAnErrorWritingIt(t *testing.T) {
	w := traceWriter{failAfter: 1}
	r := events.NewRecorder(time.Now(), 10, events.NewTrace(&w, 1<<20))
	for i := range 3 {
		r.Record(events.Event{Kind: events.Connected, Connection: uint64(i + 1)})
	}
	s := r.Trace()
	if s.Complete || !errors.Is(s.Err, errDiskFull) || s.Size != int64(bytes.IndexByte(w.Bytes(), '\n')+1) {
		t.Errorf("trace status = %+v, want incomplete with %v after its first line", s, errDiskFull)
	}
	if w.writes != 2 {
		t.Errorf("the trace was written %d times, want none after the error", w.writes)
	}
}

func TestTraceIsIncompleteIfClosingItFails(t *testing.T) {
	w := traceWriter{closeErr: errDiskFull}
	r := events.NewRecorder(time.Now(), 10, events.NewTrace(&w, 1<<20))
	r.Record(events.Event{Kind: events.Connected, Connection: 1})
	r.Close()
	if s := r.Trace(); s.Complete || !errors.Is(s.Err, errDiskFull) {
		t.Errorf("trace status = %+v, want incomplete with %v", s, errDiskFull)
	}
}

func TestTraceIsIncompleteIfAnEventArrivesAfterTheRunEnded(t *testing.T) {
	var w traceWriter
	r := events.NewRecorder(time.Now(), 10, events.NewTrace(&w, 1<<20))
	r.Record(events.Event{Kind: events.Connected, Connection: 1})
	r.Close()
	r.Record(events.Event{Kind: events.Disconnected, Connection: 1})
	if s := r.Trace(); s.Complete || s.Err == nil {
		t.Errorf("trace status = %+v, want incomplete with an error", s)
	}
	if got := kindsAndIDs(traceLines(t, w.Bytes())); !slices.Equal(got, []string{"connected 1"}) {
		t.Errorf("the trace holds %v, want only the event before Close", got)
	}
}

func TestARecorderWithoutATraceDescribesNone(t *testing.T) {
	r := events.NewRecorder(time.Now(), 10, nil)
	r.Record(events.Event{Kind: events.Connected, Connection: 1})
	r.Close()
	if s := r.Trace(); s != (events.TraceStatus{}) {
		t.Errorf("trace status = %+v, want the zero status", s)
	}
}

var errDiskFull = errors.New("disk full")

// traceWriter collects a trace, failing each write after its first
// failAfter, if set, and its Close with closeErr.
type traceWriter struct {
	bytes.Buffer
	failAfter int
	closeErr  error
	writes    int
	closed    bool
}

func (w *traceWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.failAfter > 0 && w.writes > w.failAfter {
		// Part of the line reaches the file.
		w.Buffer.Write(p[:len(p)/2])
		return len(p) / 2, errDiskFull
	}
	return w.Buffer.Write(p)
}

func (w *traceWriter) Close() error {
	w.closed = true
	return w.closeErr
}

func traceLines(t *testing.T, b []byte) []events.Event {
	t.Helper()
	var lines []events.Event
	s := bufio.NewScanner(bytes.NewReader(b))
	for s.Scan() {
		var e events.Event
		if err := json.Unmarshal(s.Bytes(), &e); err != nil {
			t.Fatalf("trace line %q: %v", s.Text(), err)
		}
		lines = append(lines, e)
	}
	return lines
}

func kindsAndIDs(lines []events.Event) []string {
	var got []string
	for _, e := range lines {
		got = append(got, string(e.Kind)+" "+strconv.FormatUint(e.ID, 10))
	}
	return got
}

// line returns e as the trace writes it.
func line(t *testing.T, e events.Event) []byte {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}
