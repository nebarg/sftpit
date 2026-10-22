package faults_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

func at(d time.Duration) *faults.Range[time.Duration] {
	return &faults.Range[time.Duration]{Min: d, Max: d}
}

var stat = faults.Match{Operations: ops(faults.Stat)}

func TestAWindowLimitsARuleToASpan(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		e := newEngine(t, faults.Rule{ID: "bad", Match: stat, Trigger: &faults.Trigger{Anchor: faults.Run, Window: &faults.Window{From: 10 * time.Second, Until: 15 * time.Second}}, Action: failure})
		byConn := newEngine(t, faults.Rule{ID: "bad", Match: stat, Trigger: &faults.Trigger{Anchor: faults.Connection, Window: &faults.Window{From: time.Second, Until: 2 * time.Second}}, Action: failure})
		// The connection's window starts a second after it authenticated,
		// 5 seconds into the run, and the run's ten seconds into the run.
		time.Sleep(5 * time.Second)
		run := session(e, "test", "")
		conn := byConn.Session(faults.Client{User: "test", Connection: 1, Authenticated: time.Now()}).Decide
		for _, step := range []struct {
			sleep     time.Duration
			run, conn bool
		}{
			{0, false, false},
			{time.Second, false, true},
			{999 * time.Millisecond, false, true},
			{time.Millisecond, false, false},
			{4 * time.Second, true, false},
			{3999 * time.Millisecond, true, false},
			{time.Millisecond, false, false},
		} {
			time.Sleep(step.sleep)
			if got := run(on(&sftpwire.Stat{}, "/f")) != nil; got != step.run {
				t.Errorf("at %v of the run, the run's window applied: %v", time.Since(start), got)
			}
			if got := conn(on(&sftpwire.Stat{}, "/f")) != nil; got != step.conn {
				t.Errorf("at %v of the run, the connection's window applied: %v", time.Since(start), got)
			}
		}
		if got := e.Counts()["bad"]; got != (faults.Counts{Matched: 2, Selected: 2, Fired: 2}) {
			t.Errorf("counts = %+v, want only the stats in the window matched", got)
		}
	})
}

func TestAMomentAppliesToTheFirstRequestItGetsAfterIt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEngine(t,
			faults.Rule{ID: "first", Priority: 1, Match: faults.Match{Operations: ops(faults.Stat), Occurrence: []uint64{1}}, Action: denied},
			faults.Rule{ID: "later", Priority: 2, Match: stat, Trigger: &faults.Trigger{Anchor: faults.Run, At: at(2 * time.Second)}, Action: failure},
		)
		decide := session(e, "test", "")
		for i, step := range []struct {
			sleep time.Duration
			want  sftpproxy.Action
		}{
			{time.Second, denied},
			{0, nil},
			// The moment passes; the first stat after it is the rule's.
			{2 * time.Second, failure},
			{0, nil},
		} {
			time.Sleep(step.sleep)
			if got := decide(on(&sftpwire.Stat{}, "/f")); got != step.want {
				t.Errorf("stat %d got %#v, want %#v", i+1, got, step.want)
			}
		}
	})
}

func TestEachConnectionHasItsOwnMoment(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEngine(t, faults.Rule{ID: "r", Match: stat, Trigger: &faults.Trigger{Anchor: faults.Connection, At: at(time.Second)}, Action: failure})
		start := time.Now()
		first := e.Session(faults.Client{User: "test", Connection: 1, Authenticated: start}).Decide
		time.Sleep(500 * time.Millisecond)
		second := e.Session(faults.Client{User: "test", Connection: 2, Authenticated: time.Now()}).Decide
		time.Sleep(600 * time.Millisecond)
		if first(on(&sftpwire.Stat{}, "/f")) == nil || second(on(&sftpwire.Stat{}, "/f")) != nil {
			t.Error("1.1s into the first connection and 0.6s into the second, want only the first's moment passed")
		}
		time.Sleep(time.Second)
		if first(on(&sftpwire.Stat{}, "/f")) != nil || second(on(&sftpwire.Stat{}, "/f")) == nil {
			t.Error("want each connection's moment to apply once")
		}
		again := e.Session(faults.Client{User: "test", Connection: 1, Authenticated: start}).Decide
		if again(on(&sftpwire.Stat{}, "/f")) != nil {
			t.Error("another session on the first connection applied its moment again")
		}
	})
}

func TestAMissedMomentIsUsedUp(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEngine(t, faults.Rule{ID: "r", Match: stat, Probability: probability(0), Trigger: &faults.Trigger{Anchor: faults.Run, At: at(time.Second)}, Action: failure},
			faults.Rule{ID: "after", Priority: 1, Match: stat, Trigger: &faults.Trigger{Anchor: faults.Run, At: at(time.Second)}, Action: denied})
		time.Sleep(time.Second)
		decide := session(e, "test", "")
		if got := decide(on(&sftpwire.Stat{}, "/f")); got != denied {
			t.Errorf("the first stat got %#v, want the next rule's after the first missed", got)
		}
		if got := decide(on(&sftpwire.Stat{}, "/f")); got != nil {
			t.Errorf("the second stat got %#v, want both moments used up", got)
		}
		if got := e.Counts()["r"]; got != (faults.Counts{Matched: 1}) {
			t.Errorf("the missed rule's counts = %+v, want it to match only the stat it missed", got)
		}
	})
}

func TestConnectionActionsAreTimedForEachSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs bytes.Buffer
		reset := sftpproxy.Drop{Reset: true}
		atRandom := faults.Range[time.Duration]{Min: time.Second, Max: time.Minute}
		e, err := faults.New([]faults.Rule{
			{ID: "per-connection", Match: faults.Match{User: "a"}, Trigger: &faults.Trigger{Anchor: faults.Connection, At: &atRandom}, Action: reset},
			{ID: "once-in-the-run", MaxTriggers: 1, Trigger: &faults.Trigger{Anchor: faults.Run, At: at(10 * time.Second)}, Action: sftpproxy.EndSession{}},
		}, testSeed, slog.New(slog.NewTextHandler(&logs, nil)))
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		time.Sleep(time.Second)
		authenticated := time.Now()
		var timers [][]sftpproxy.Timer
		for i, user := range []string{"a", "a", "b"} {
			timers = append(timers, e.Session(faults.Client{User: user, Connection: uint64(i + 1), Authenticated: authenticated}).Timers())
		}
		// Another session on a's first connection shares its moment.
		shared := e.Session(faults.Client{User: "a", Connection: 1, Authenticated: authenticated}).Timers()
		time.Sleep(10 * time.Second)
		if late := e.Session(faults.Client{User: "b", Authenticated: time.Now()}).Timers(); len(late) != 0 {
			t.Errorf("a session after the run's moment got timers %+v", late)
		}

		for i, user := range []string{"a", "a", "b"} {
			var want []sftpproxy.Timer
			if user == "a" {
				key := faults.Key{Rule: "per-connection", Choice: "at", User: "a", Ordinal: uint64(i + 1)}
				want = append(want, sftpproxy.Timer{At: authenticated.Add(faults.Between(testSeed.Draw(key), atRandom.Min, atRandom.Max)), Action: reset})
			}
			want = append(want, sftpproxy.Timer{At: start.Add(10 * time.Second), Action: sftpproxy.EndSession{}})
			got := timers[i]
			if len(got) != len(want) {
				t.Fatalf("session %d of %s got %d timers, want %d", i+1, user, len(got), len(want))
			}
			for j := range want {
				if got[j].At != want[j].At || got[j].Action != want[j].Action || got[j].Reserve == nil {
					t.Errorf("session %d of %s timer %d = %+v, want %+v with a Reserve", i+1, user, j, got[j], want[j])
				}
			}
		}
		if timers[0][0].At == timers[1][0].At {
			t.Errorf("both of a's sessions drew the moment %v", timers[0][0].At)
		}

		if !timers[0][1].Reserve() || timers[2][0].Reserve() {
			t.Error("the run's moment fired in more than one session, beyond max_triggers")
		}
		if shared[0].At != timers[0][0].At {
			t.Errorf("a second session on a connection was timed for %v, want the connection's moment, %v", shared[0].At, timers[0][0].At)
		}
		if !timers[0][0].Reserve() || shared[0].Reserve() {
			t.Error("a connection's moment fired in none or both of its sessions")
		}
		counts := e.Counts()
		if want := (faults.Counts{Matched: 2, Selected: 2, Fired: 1}); counts["per-connection"] != want {
			t.Errorf("per-connection counts = %+v, want %+v", counts["per-connection"], want)
		}
		if want := (faults.Counts{Matched: 5, Selected: 4, Fired: 1}); counts["once-in-the-run"] != want {
			t.Errorf("once-in-the-run counts = %+v, want %+v", counts["once-in-the-run"], want)
		}
		for _, line := range []string{
			`level=INFO msg="rule fired" rule=once-in-the-run user=a anchor=run at=10s`,
			`level=INFO msg="rule suppressed" rule=once-in-the-run user=b anchor=run at=10s reason=max_triggers`,
			`level=INFO msg="rule fired" rule=per-connection user=a anchor=connection at=`,
		} {
			if !strings.Contains(logs.String(), line) {
				t.Errorf("logs lack %s:\n%s", line, logs.String())
			}
		}
	})
}

func TestDownloadsAreTimedFromTheirOpenForReading(t *testing.T) {
	e := newEngine(t, faults.Rule{ID: "r", Match: faults.Match{Operations: ops(faults.Read)}, Trigger: &faults.Trigger{Anchor: faults.Transfer, At: at(time.Second)}, Action: sftpproxy.EndSession{}})
	decide := session(e, "test", "")
	if decide(openFor("/f", sftpwire.OpenWrite)) != nil {
		t.Error("an upload got a download's moment")
	}
	if a, ok := decide(openFor("/f", sftpwire.OpenRead)).(sftpproxy.Timed); !ok || a.After != time.Second {
		t.Errorf("the download's open got %#v, want its moment", a)
	}
}

func TestAFixedMomentDrawsNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs bytes.Buffer
		e, err := faults.New([]faults.Rule{
			{ID: "r", Match: stat, Trigger: &faults.Trigger{Anchor: faults.Run, At: at(time.Second)}, Action: failure},
		}, testSeed, slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
		if session(e, "test", "")(on(&sftpwire.Stat{}, "/f")) == nil {
			t.Error("the stat after the moment got no fault")
		}
		if strings.Contains(logs.String(), "msg=decision") {
			t.Errorf("a fixed moment logged a decision:\n%s", logs.String())
		}
	})
}

func TestTransfersAreTimedFromTheirOpen(t *testing.T) {
	cutoffs := faults.Range[time.Duration]{Min: time.Second, Max: 10 * time.Second}
	e := newEngine(t, faults.Rule{
		ID:      "reset-into-upload",
		Match:   faults.Match{Operations: ops(faults.Write), Path: faults.Location{Kind: faults.Under, Pattern: "/in"}},
		Trigger: &faults.Trigger{Anchor: faults.Transfer, At: &cutoffs},
		Action:  sftpproxy.Drop{Reset: true},
	})
	decide := session(e, "test", "")
	if decide(on(&sftpwire.Write{}, "/in/a.csv")) != nil || decide(openFor("/in/a.csv", sftpwire.OpenRead)) != nil {
		t.Error("a write or a download got the upload's moment, which belongs to its open")
	}
	a, ok := decide(openFor("/in/a.csv", sftpwire.OpenWrite)).(sftpproxy.Timed)
	key := faults.Key{Rule: "reset-into-upload", Choice: "at", User: "test", Path: "/in/a.csv", Operation: "open_write", Ordinal: 1}
	if want := faults.Between(testSeed.Draw(key), cutoffs.Min, cutoffs.Max); !ok || a.After != want || a.Action != (sftpproxy.Drop{Reset: true}) || a.Reserve == nil {
		t.Fatalf("the upload's open got %#v, want a reset after %v", a, want)
	}
	if got := e.Counts()["reset-into-upload"]; got != (faults.Counts{Matched: 1, Selected: 1}) {
		t.Errorf("counts before the moment = %+v", got)
	}
	if !a.Reserve() {
		t.Error("the moment was refused")
	}
	if got := e.Counts()["reset-into-upload"]; got != (faults.Counts{Matched: 1, Selected: 1, Fired: 1}) {
		t.Errorf("counts = %+v, want the moment fired", got)
	}
}
