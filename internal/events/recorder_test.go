package events_test

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/events"
)

func TestRecorderNumbersAndTimesEachEvent(t *testing.T) {
	start := time.Now().Add(-time.Second)
	r := events.NewRecorder(start, 10)
	r.Record(events.Event{Kind: events.Connected, Connection: 1})
	r.Record(events.Event{Kind: events.Authenticated, Connection: 1, User: "test"})
	got := r.Events().Events
	if len(got) != 2 || got[0].ID != 1 || got[1].ID != 2 {
		t.Fatalf("events = %+v, want IDs 1 and 2", got)
	}
	for _, e := range got {
		if e.Time.Location() != time.UTC || time.Duration(e.Elapsed) < time.Second {
			t.Errorf("event %d at %v, %v into the run, want UTC and at least 1s in", e.ID, e.Time, time.Duration(e.Elapsed))
		}
	}
}

func TestRecorderKeepsTheLatestEvents(t *testing.T) {
	r := events.NewRecorder(time.Now(), 3)
	if last := r.Events().Last; last != 0 {
		t.Errorf("Last of no events = %d, want 0", last)
	}
	for i := range 5 {
		r.Record(events.Event{Kind: events.Connected, Connection: uint64(i + 1)})
	}
	p := r.Events()
	if ids := ids(p.Events); !slices.Equal(ids, []uint64{3, 4, 5}) || p.First != 3 || p.Last != 5 {
		t.Errorf("page = %v, first %d, last %d; want 3 to 5, first 3, last 5", ids, p.First, p.Last)
	}
}

func TestRecorderCountsWaits(t *testing.T) {
	r := events.NewRecorder(time.Now(), 2)
	stall := &events.Fault{Type: "stall"}
	freeze := &events.Fault{Type: "freeze_connection"}
	for _, e := range []events.Event{
		{Kind: events.FaultInjected, Rule: "stuck", Fault: stall},
		{Kind: events.FaultInjected, Rule: "stuck", Fault: stall},
		{Kind: events.FaultInjected, Rule: "frozen", Fault: freeze},
		{Kind: events.FaultInjected, Rule: "denied", Fault: &events.Fault{Type: "fail"}},
		{Kind: events.FaultEnded, Rule: "stuck", Fault: stall, Reason: "canceled"},
		{Kind: events.FaultEnded, Rule: "frozen", Fault: freeze, Reason: "limit"},
	} {
		r.Record(e)
	}
	// The counts outlast the events, which the recorder has no room for.
	if stalls, freezes := r.Waiting("stall"), r.Waiting("freeze_connection"); stalls != 1 || freezes != 0 {
		t.Errorf("waiting: %d stalls and %d freezes, want 1 and 0", stalls, freezes)
	}
}

func TestEventsWriteDurationsInMilliseconds(t *testing.T) {
	e := events.Event{ID: 1, Kind: events.Operation, Elapsed: events.Millis(1500 * time.Microsecond), Duration: events.Millis(2 * time.Second), RequestID: new(uint32(0))}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["elapsed_ms"] != 1.5 || decoded["duration_ms"] != 2000.0 || decoded["request_id"] != 0.0 {
		t.Errorf("event = %s, want 1.5 ms elapsed, 2000 ms taken and request 0", b)
	}
	var back events.Event
	if err := json.Unmarshal(b, &back); err != nil || back.Elapsed != e.Elapsed || back.Duration != e.Duration {
		t.Errorf("read back as %+v (%v), want the same durations", back, err)
	}
}

func ids(es []events.Event) []uint64 {
	var ids []uint64
	for _, e := range es {
		ids = append(ids, e.ID)
	}
	return ids
}
