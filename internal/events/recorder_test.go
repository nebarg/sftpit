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
	r := events.NewRecorder(start, 10, nil)
	r.Record(events.Event{Kind: events.Connected, Connection: 1})
	r.Record(events.Event{Kind: events.Authenticated, Connection: 1, User: "test"})
	got := r.Events(0, 100, events.Filter{}).Events
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
	r := events.NewRecorder(time.Now(), 3, nil)
	for i := range 5 {
		r.Record(events.Event{Kind: events.Connected, Connection: uint64(i + 1)})
	}
	p := r.Events(0, 100, events.Filter{})
	if ids := ids(p.Events); !slices.Equal(ids, []uint64{3, 4, 5}) || p.First != 3 || p.Next != 5 {
		t.Errorf("page = %v, first %d, next %d; want 3 to 5, first 3, next 5", ids, p.First, p.Next)
	}
	if p := r.Events(5, 100, events.Filter{}); len(p.Events) != 0 || p.Next != 5 {
		t.Errorf("after the last event: %v, next %d; want none, next 5", ids(p.Events), p.Next)
	}
}

func TestRecorderPagesThroughMatchingEvents(t *testing.T) {
	r := events.NewRecorder(time.Now(), 100, nil)
	for _, e := range []events.Event{
		{Kind: events.Connected, Connection: 1},
		{Kind: events.Operation, Connection: 1, User: "test", Path: "/a"},
		{Kind: events.Operation, Connection: 2, User: "partner-b", Path: "/b"},
		{Kind: events.FaultInjected, Connection: 1, User: "test", Path: "/c", Target: "/a", Rule: "deny", Fault: &events.Fault{Type: "fail"}},
		{Kind: events.Operation, Connection: 1, User: "test", Path: "/a", Rule: "deny"},
	} {
		r.Record(e)
	}
	tests := []struct {
		name   string
		filter events.Filter
		want   []uint64
	}{
		{"everything", events.Filter{}, []uint64{1, 2, 3, 4, 5}},
		{"a kind", events.Filter{Kinds: []events.Kind{events.Operation}}, []uint64{2, 3, 5}},
		{"kinds", events.Filter{Kinds: []events.Kind{events.Connected, events.FaultInjected}}, []uint64{1, 4}},
		{"a connection", events.Filter{Connection: 2}, []uint64{3}},
		{"a user", events.Filter{User: "test"}, []uint64{2, 4, 5}},
		{"a path or target", events.Filter{Path: "/a"}, []uint64{2, 4, 5}},
		{"a rule", events.Filter{Rule: "deny"}, []uint64{4, 5}},
	}
	for _, tt := range tests {
		if got := ids(r.Events(0, 100, tt.filter).Events); !slices.Equal(got, tt.want) {
			t.Errorf("%s: %v, want %v", tt.name, got, tt.want)
		}
	}

	// A page stops before the first event it has no room for, matching or
	// not, so the next carries on from there.
	filter := events.Filter{User: "test"}
	p := r.Events(0, 2, filter)
	if got := ids(p.Events); !slices.Equal(got, []uint64{2, 4}) || p.Next != 4 {
		t.Fatalf("first page = %v, next %d; want 2 and 4, next 4", got, p.Next)
	}
	if p := r.Events(p.Next, 2, filter); !slices.Equal(ids(p.Events), []uint64{5}) || p.Next != 5 {
		t.Errorf("second page = %v, next %d; want 5, next 5", ids(p.Events), p.Next)
	}
}

func TestRecorderWakesItsFollowers(t *testing.T) {
	r := events.NewRecorder(time.Now(), 10, nil)
	changed := r.Changed()
	select {
	case <-changed:
		t.Fatal("Changed is closed before any event")
	default:
	}
	r.Record(events.Event{Kind: events.Connected})
	<-changed

	changed = r.Changed()
	r.Close()
	<-changed
	<-r.Changed()
	if !r.Closed() {
		t.Error("Closed = false after Close")
	}
	// A run's late events are still kept.
	r.Record(events.Event{Kind: events.Disconnected})
	if got := ids(r.Events(0, 10, events.Filter{}).Events); !slices.Equal(got, []uint64{1, 2}) {
		t.Errorf("events = %v, want both", got)
	}
}

func TestRecorderCountsWaitsAndCancellations(t *testing.T) {
	r := events.NewRecorder(time.Now(), 2, nil)
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
	if stuck, frozen := r.Canceled("stuck"), r.Canceled("frozen"); stuck != 1 || frozen != 0 {
		t.Errorf("canceled: %d of stuck and %d of frozen, want 1 and 0", stuck, frozen)
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
