package faults_test

import (
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

func TestAListenerDownAtAMomentOfTheRunIsTimedOnceForTheRun(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		e := newEngine(t, faults.Rule{ID: "outage", Trigger: &faults.Trigger{Anchor: faults.Run, At: at(10 * time.Second)}, Duration: someSeconds, Action: drawnOutage})

		if got := e.Session(faults.Client{User: "test", Connection: 1, Authenticated: start}).Timers(); len(got) != 0 {
			t.Errorf("a session's timers = %+v, want none: the run takes the listener down", got)
		}
		timers := e.Timers()
		if len(timers) != 1 {
			t.Fatalf("Timers = %+v, want one", timers)
		}
		down, ok := timers[0].Action.(sftpproxy.ListenerDown)
		if !timers[0].At.Equal(start.Add(10*time.Second)) || !ok || !down.CloseExisting || down.Duration < time.Second || down.Duration > time.Minute {
			t.Errorf("timer = %+v, want a ListenerDown closing every connection 10s into the run, for 1s to 1m", timers[0])
		}
		if !timers[0].Reserve() {
			t.Error("Reserve declined the outage")
		}
		if got := e.Rules().Counts["outage"]; got != (faults.Counts{Matched: 1, Selected: 1, Fired: 1}) {
			t.Errorf("counts = %+v, want the run's outage selected and fired once", got)
		}
	})
}

func TestAListenerDownDrawsItsDurationForEachConnectionAndTransfer(t *testing.T) {
	byConnection := newEngine(t, faults.Rule{ID: "outage", Trigger: &faults.Trigger{Anchor: faults.Connection, At: at(time.Second)}, Duration: someSeconds, Action: drawnOutage})
	durationOf := func(timers []sftpproxy.Timer) time.Duration {
		t.Helper()
		if len(timers) != 1 {
			t.Fatalf("timers = %+v, want one", timers)
		}
		return timers[0].Action.(sftpproxy.ListenerDown).Duration
	}
	first := durationOf(byConnection.Session(faults.Client{User: "test", Connection: 1}).Timers())
	again := durationOf(byConnection.Session(faults.Client{User: "test", Connection: 1}).Timers())
	other := durationOf(byConnection.Session(faults.Client{User: "test", Connection: 2}).Timers())
	if first != again || first == other || first < time.Second || first > time.Minute {
		t.Errorf("outages of %v and %v on connection 1, and %v on connection 2, want one draw from 1s to 1m per connection", first, again, other)
	}

	byTransfer := newEngine(t, faults.Rule{ID: "outage", Match: faults.Match{Operations: ops(faults.Write)}, Trigger: &faults.Trigger{Anchor: faults.Transfer, At: at(time.Second)}, Duration: someSeconds, Action: drawnOutage})
	decide := session(byTransfer, "test", "")
	timed, ok := decide(openFor("/f", sftpwire.OpenWrite)).(sftpproxy.Timed)
	if !ok {
		t.Fatalf("the open got %#v, want a Timed", timed)
	}
	if down := timed.Action.(sftpproxy.ListenerDown); timed.After != time.Second || down.Duration < time.Second || down.Duration > time.Minute {
		t.Errorf("the open got %+v, want an outage a second after it, for 1s to 1m", timed)
	}
}

func TestAListenerDownAtLogin(t *testing.T) {
	e := newEngine(t, faults.Rule{ID: "outage", MaxTriggers: 1, Match: faults.Match{Operations: ops(faults.Authenticate)}, Action: outage})
	if got := e.Authenticate(faults.Client{User: "test"}); got != outage {
		t.Errorf("the first login got %#v, want %#v", got, outage)
	}
	if got := e.Authenticate(faults.Client{User: "test"}); got != nil {
		t.Errorf("the second login got %#v, want nothing once max_triggers is used up", got)
	}
}

func TestARunWideOutageMatchesNoUser(t *testing.T) {
	_, err := faults.New([]faults.Rule{{ID: "r", Match: faults.Match{User: "test"}, Trigger: &faults.Trigger{Anchor: faults.Run, At: at(time.Second)}, Action: outage}}, nil, testSeed, nil)
	if want := "a listener_down at a moment of the run takes the listener down for everyone, so it matches no user or key"; err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("New = %v, want an error about %q", err, want)
	}
}
