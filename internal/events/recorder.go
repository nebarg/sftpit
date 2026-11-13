package events

import (
	"sync"
	"time"
)

// Recorder keeps the latest events of a run, numbering and timing each as
// it is recorded, and counts the faults whose waits are in progress. Its
// methods are safe for concurrent use.
type Recorder struct {
	start time.Time
	limit int

	mu sync.Mutex
	// ring holds the latest events, oldest first from head once it is
	// full.
	ring []Event
	head int
	next uint64
	// waiting counts the faults whose waits are in progress, by type.
	waiting map[FaultType]int
}

// NewRecorder returns a recorder for a run that started at start, which
// keeps its latest limit events.
func NewRecorder(start time.Time, limit int) *Recorder {
	return &Recorder{
		start:   start,
		limit:   limit,
		next:    1,
		waiting: make(map[FaultType]int),
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
}

// count keeps the counts of waits up to date with e. r.mu must be held.
func (r *Recorder) count(e Event) {
	switch {
	case e.Kind == FaultInjected && e.Fault.Type.Waits():
		r.waiting[e.Fault.Type]++
	case e.Kind == FaultEnded:
		r.waiting[e.Fault.Type]--
	}
}

// Page is the events a Recorder keeps.
type Page struct {
	Events []Event

	// First is the ID of the oldest event kept, or of the next to be
	// recorded if none is. Events numbered before it are gone.
	First uint64

	// Last is the ID of the latest event recorded, or 0 if none has been.
	Last uint64
}

// Events returns the events the recorder keeps, oldest first.
func (r *Recorder) Events() Page {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := Page{Events: make([]Event, 0, len(r.ring)), First: r.next - uint64(len(r.ring)), Last: r.next - 1}
	for i := range r.ring {
		p.Events = append(p.Events, r.ring[(r.head+i)%len(r.ring)])
	}
	return p
}

// Waiting returns how many faults of type typ, such as StallFault, are
// waiting now.
func (r *Recorder) Waiting(typ FaultType) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.waiting[typ]
}
