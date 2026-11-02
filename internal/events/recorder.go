package events

import (
	"slices"
	"sync"
	"time"
)

// Recorder keeps the latest events of a run, numbering and timing each as
// it is recorded, and counts the faults whose waits are in progress and
// those that a change of rules canceled. Its methods are safe for
// concurrent use.
type Recorder struct {
	start time.Time
	limit int

	mu sync.Mutex
	// ring holds the latest events, oldest first from head once it is
	// full.
	ring []Event
	head int
	next uint64
	// changed is closed, and replaced, as each event is recorded, and
	// closed for good when the recorder is.
	changed chan struct{}
	closed  bool
	// waiting counts the faults whose waits are in progress, by type, and
	// canceled the waits that a change of rules ended, by rule.
	waiting  map[string]int
	canceled map[string]uint64
}

// NewRecorder returns a recorder for a run that started at start, which
// keeps its latest limit events.
func NewRecorder(start time.Time, limit int) *Recorder {
	return &Recorder{
		start:    start,
		limit:    limit,
		next:     1,
		changed:  make(chan struct{}),
		waiting:  make(map[string]int),
		canceled: make(map[string]uint64),
	}
}

// Record numbers e, times it now and keeps it, in place of the oldest
// event if the recorder is full.
func (r *Recorder) Record(e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	e.ID, e.Time, e.Elapsed = r.next, now.UTC(), Millis(now.Sub(r.start))
	r.next++
	r.count(e)
	if len(r.ring) < r.limit {
		r.ring = append(r.ring, e)
	} else {
		r.ring[r.head] = e
		r.head = (r.head + 1) % r.limit
	}
	if !r.closed {
		close(r.changed)
		r.changed = make(chan struct{})
	}
}

// count keeps the counts of waits up to date with e. r.mu must be held.
func (r *Recorder) count(e Event) {
	switch {
	case e.Kind == FaultInjected && waits(e.Fault.Type):
		r.waiting[e.Fault.Type]++
	case e.Kind == FaultEnded:
		r.waiting[e.Fault.Type]--
		if e.Reason == "canceled" {
			r.canceled[e.Rule]++
		}
	}
}

// waits reports whether a fault of type typ waits, and ends with a
// FaultEnded event.
func waits(typ string) bool {
	return typ == "delay" || typ == "stall" || typ == "freeze_connection"
}

// Filter selects events. A zero field matches every event.
type Filter struct {
	Kinds      []Kind
	Connection uint64
	User       string
	// Path matches an event's Path or Target.
	Path string
	Rule string
}

func (f Filter) matches(e Event) bool {
	return (len(f.Kinds) == 0 || slices.Contains(f.Kinds, e.Kind)) &&
		(f.Connection == 0 || f.Connection == e.Connection) &&
		(f.User == "" || f.User == e.User) &&
		(f.Path == "" || f.Path == e.Path || f.Path == e.Target) &&
		(f.Rule == "" || f.Rule == e.Rule)
}

// Page is a page of the events a Recorder keeps.
type Page struct {
	Events []Event `json:"events"`

	// First is the ID of the oldest event kept, or of the next to be
	// recorded if none is. Events numbered before it are gone.
	First uint64 `json:"first_id"`

	// Next is the ID to ask for events after, to continue: that of the
	// last event the page looked at.
	Next uint64 `json:"next"`
}

// Events returns up to limit of the events numbered after after that f
// matches, oldest first.
func (r *Recorder) Events(after uint64, limit int, f Filter) Page {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := Page{Events: []Event{}, First: r.next - uint64(len(r.ring)), Next: max(after, r.next-1)}
	for i := range r.ring {
		e := r.ring[(r.head+i)%len(r.ring)]
		if e.ID <= after {
			continue
		}
		if len(p.Events) == limit {
			p.Next = e.ID - 1
			break
		}
		if f.matches(e) {
			p.Events = append(p.Events, e)
		}
	}
	return p
}

// Changed returns a channel that is closed once another event is recorded,
// or the recorder is closed.
func (r *Recorder) Changed() <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.changed
}

// Close marks the end of the run, waking every reader waiting on Changed.
// The recorder keeps its events, and records any more it is given.
func (r *Recorder) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		close(r.changed)
	}
}

// Closed reports whether Close has been called.
func (r *Recorder) Closed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

// Waiting returns how many faults of type typ, such as stall or
// freeze_connection, are waiting now.
func (r *Recorder) Waiting(typ string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.waiting[typ]
}

// Canceled returns how many waits of rule's faults a change of rules has
// canceled.
func (r *Recorder) Canceled(rule string) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.canceled[rule]
}
