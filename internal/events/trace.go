package events

import (
	"encoding/json"
	"errors"
	"io"
)

// errAfterClose is a trace's error once an event arrives after its run
// ended and the trace was closed.
var errAfterClose = errors.New("events: an event arrived after the trace was closed")

// TraceFull is the last line of a trace that reached its limit. Its ID is
// that of the first event the trace left out. A Recorder writes it only to
// the trace, never among the events it keeps.
const TraceFull Kind = "trace_full"

// Trace writes a run's events to w as JSON Lines, one event a line, in the
// order they are recorded, until the next line would take it past limit
// bytes. It then writes a TraceFull line, which may take it past limit, and
// nothing more, so a reader of the file alone can tell that it is
// incomplete. A Trace is not safe for concurrent use; a Recorder serialises
// its writes.
type Trace struct {
	w     io.WriteCloser
	limit int64

	size   int64
	full   bool
	err    error
	closed bool
}

// NewTrace returns a trace that writes to w, until the next line would
// take it past limit bytes.
func NewTrace(w io.WriteCloser, limit int64) *Trace {
	return &Trace{w: w, limit: limit}
}

// TraceStatus describes a trace: the bytes of whole lines it has written,
// and whether it holds every event recorded so far. A trace stops at its
// limit, or at the first error writing it, which Err gives.
type TraceStatus struct {
	Size     int64
	Complete bool
	Err      error
}

func (t *Trace) write(e Event) {
	if t.full || t.err != nil {
		return
	}
	if t.closed {
		t.err = errAfterClose
		return
	}
	line, err := json.Marshal(e)
	if err != nil {
		t.err = err
		return
	}
	line = append(line, '\n')
	if t.size+int64(len(line)) > t.limit {
		t.full = true
		line, err = json.Marshal(Event{ID: e.ID, Time: e.Time, Elapsed: e.Elapsed, Kind: TraceFull})
		if err != nil {
			t.err = err
			return
		}
		line = append(line, '\n')
	}
	// A short write leaves part of a line, which Size leaves out.
	if _, err := t.w.Write(line); err != nil {
		t.err = err
		return
	}
	t.size += int64(len(line))
}

func (t *Trace) status() TraceStatus {
	return TraceStatus{Size: t.size, Complete: !t.full && t.err == nil, Err: t.err}
}

// close closes the trace's writer. An event after it leaves the trace
// incomplete, as does an error closing the writer, which may have lost
// what it was given.
func (t *Trace) close() {
	if t.closed {
		return
	}
	t.closed = true
	if err := t.w.Close(); err != nil && t.err == nil {
		t.err = err
	}
}
