package faults_test

import (
	"bytes"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

func TestAChangeReplacesTheRulesAsTheNextRevision(t *testing.T) {
	var logs bytes.Buffer
	kept := faults.Rule{ID: "kept", Match: faults.Match{Operations: ops(faults.Stat), Occurrence: []uint64{2}}, Action: failure}
	edited := faults.Rule{ID: "edited", Priority: 1, Match: faults.Match{Operations: ops(faults.LStat), Occurrence: []uint64{1}}, Action: failure}
	removed := failOn("removed", faults.Match{Operations: ops(faults.Mkdir)})
	e, err := faults.New([]faults.Rule{edited, kept, removed}, nil, testSeed, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	decide := session(e, "test", "")
	decide(on(&sftpwire.Stat{}, "/f"))
	decide(on(&sftpwire.LStat{}, "/f"))
	decide(on(&sftpwire.Mkdir{}, "/d"))

	edited.Action = denied
	added := failOn("added", faults.Match{Operations: ops(faults.Rmdir)})
	if _, err := e.Replace(1, []faults.Rule{edited, added, kept}, nil); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	set := e.Rules()
	ids := func(rules []faults.Rule) []string {
		var ids []string
		for _, r := range rules {
			ids = append(ids, r.ID)
		}
		return ids
	}
	if set.Revision != 2 || e.Revision() != 2 || !slices.Equal(ids(set.Rules), []string{"added", "kept", "edited"}) {
		t.Errorf("rules = revision %d (Revision %d), %v; want revision 2 with added, kept and edited in the order they are tried", set.Revision, e.Revision(), ids(set.Rules))
	}
	wantCounts := map[string]faults.Counts{"kept": {Matched: 1}, "edited": {}, "added": {}}
	if len(set.Counts) != len(wantCounts) {
		t.Errorf("counts = %+v, want %+v", set.Counts, wantCounts)
	}
	for id, want := range wantCounts {
		if set.Counts[id] != want {
			t.Errorf("%s counts = %+v, want %+v", id, set.Counts[id], want)
		}
	}

	if got := decide(on(&sftpwire.Stat{}, "/f")); got != failure {
		t.Errorf("the second stat got %#v, want the kept rule's second occurrence", got)
	}
	if got := decide(on(&sftpwire.LStat{}, "/f")); got != denied {
		t.Errorf("the second lstat got %#v, want the edited rule's first occurrence since the change", got)
	}
	if got := decide(on(&sftpwire.Mkdir{}, "/d")); got != nil {
		t.Errorf("a mkdir got %#v, want nothing from the removed rule", got)
	}
	if got := decide(on(&sftpwire.Rmdir{}, "/d")); got != failure {
		t.Errorf("an rmdir got %#v, want the added rule", got)
	}
	want := `level=INFO msg="rules changed" from=1 to=2 added=[added] changed=[edited] removed=[removed] kept=[kept]`
	if !strings.Contains(logs.String(), want) {
		t.Errorf("logs lack %s:\n%s", want, logs.String())
	}
}

func TestAChangeNeedsTheCurrentRevisionAndValidRules(t *testing.T) {
	e := newEngine(t, failOn("r", stat))
	if _, err := e.Replace(2, nil, nil); !errors.Is(err, faults.ErrStaleRevision) || !strings.Contains(err.Error(), "the current revision is 1, not 2") {
		t.Errorf("Replace with a revision to come = %v, want ErrStaleRevision", err)
	}
	if _, err := e.Replace(1, []faults.Rule{failOn("r", stat), failOn("r", stat)}, nil); err == nil || !strings.Contains(err.Error(), `rule ID "r" is used twice`) {
		t.Errorf("Replace with a repeated ID = %v, want it refused", err)
	}
	if _, err := e.Replace(1, nil, nil); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if _, err := e.Replace(1, nil, nil); !errors.Is(err, faults.ErrStaleRevision) || !strings.Contains(err.Error(), "the current revision is 2, not 1") {
		t.Errorf("Replace with a revision that has gone = %v, want ErrStaleRevision", err)
	}
	if got := session(e, "test", "")(on(&sftpwire.Stat{}, "/f")); got != nil || len(e.Rules().Rules) != 0 {
		t.Errorf("a stat got %#v with rules %+v, want no rules after a change to none", got, e.Rules())
	}
}

func TestARuleAppliedLiveDrawsAfresh(t *testing.T) {
	durations := faults.Range[time.Duration]{Min: time.Millisecond, Max: time.Second}
	slow := faults.Rule{ID: "slow", Match: stat, Duration: &durations, Action: sftpproxy.Delay{}}
	e := newEngine(t, slow)
	decide := session(e, "test", "")
	durationOf := func(activation, ordinal uint64) time.Duration {
		key := faults.Key{Rule: "slow", Activation: activation, Choice: "duration", User: "test", Path: "/f", Operation: "stat", Ordinal: ordinal}
		return faults.Between(testSeed.Draw(key), durations.Min, durations.Max)
	}
	for _, step := range []struct {
		rules      []faults.Rule
		activation uint64
		ordinal    uint64
	}{
		{nil, 0, 1},
		// A rule that carries on keeps its activation and ordinals.
		{[]faults.Rule{slow}, 0, 2},
		{[]faults.Rule{}, 0, 0},
		// Applied again, it does not repeat its earlier draws.
		{[]faults.Rule{slow}, 4, 1},
	} {
		if step.rules != nil {
			if _, err := e.Replace(e.Revision(), step.rules, nil); err != nil {
				t.Fatal(err)
			}
		}
		if step.ordinal == 0 {
			continue
		}
		want := sftpproxy.Delay{Duration: durationOf(step.activation, step.ordinal)}
		if got := decide(on(&sftpwire.Stat{}, "/f")); unreleased(got) != want {
			t.Errorf("at revision %d, a stat got %#v, want %#v", e.Revision(), got, want)
		}
	}
}

func TestATriggerAnchoredToTheRunMeasuresFromTheChange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		window := faults.Rule{ID: "window", Match: stat, Trigger: &faults.Trigger{Anchor: faults.Run, Window: &faults.Window{From: 10 * time.Second, Until: 15 * time.Second}}, Action: failure}
		moment := faults.Rule{ID: "moment", Match: faults.Match{Operations: ops(faults.LStat)}, Trigger: &faults.Trigger{Anchor: faults.Run, At: at(10 * time.Second)}, Action: denied}
		e := newEngine(t)
		decide := session(e, "test", "")
		time.Sleep(20 * time.Second)
		if _, err := e.Replace(1, []faults.Rule{window, moment}, nil); err != nil {
			t.Fatal(err)
		}
		for i, step := range []struct {
			sleep       time.Duration
			stat, lstat sftpproxy.Action
		}{
			{9 * time.Second, nil, nil},
			{time.Second, failure, denied},
			{4 * time.Second, failure, nil},
			{time.Second, nil, nil},
		} {
			time.Sleep(step.sleep)
			if got := decide(on(&sftpwire.Stat{}, "/f")); got != step.stat {
				t.Errorf("stat %d got %#v, want %#v", i+1, got, step.stat)
			}
			if got := decide(on(&sftpwire.LStat{}, "/f")); got != step.lstat {
				t.Errorf("lstat %d got %#v, want %#v", i+1, got, step.lstat)
			}
		}
	})
}

func TestReleaseStallsReleasesOnlyThoseInProgress(t *testing.T) {
	var logs bytes.Buffer
	stall := sftpproxy.Stall{When: sftpproxy.Before, Limit: time.Minute}
	e, err := faults.New([]faults.Rule{{ID: "stuck", Match: stat, Action: stall}}, nil, testSeed, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if got := session(e, "test", "")(on(&sftpwire.Stat{}, "/f")); unreleased(got) != stall {
		t.Errorf("a stat got %#v, want the stall", got)
	}
	inProgress := e.Released()
	e.ReleaseStalls()
	select {
	case <-inProgress:
	default:
		t.Error("ReleaseStalls left the stalls in progress held")
	}
	later := e.Released()
	select {
	case <-later:
		t.Error("a stall that begins after ReleaseStalls is released at once")
	default:
	}
	e.ReleaseStalls()
	select {
	case <-later:
	default:
		t.Error("a second ReleaseStalls left the stalls then in progress held")
	}
	if want := `level=INFO msg="stalls released"`; strings.Count(logs.String(), want) != 2 {
		t.Errorf("logs lack two of %s:\n%s", want, logs.String())
	}
}

func TestAChangeTimesTheRunsOutagesFromIt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		someTime := faults.Range[time.Duration]{Min: time.Second, Max: time.Hour}
		outage := faults.Rule{ID: "outage", Trigger: &faults.Trigger{Anchor: faults.Run, At: &someTime}, Duration: &someTime, Action: drawnOutage}
		e := newEngine(t, outage)
		time.Sleep(time.Minute)
		if _, err := e.Replace(1, nil, nil); err != nil {
			t.Fatal(err)
		}
		changed := time.Now()
		timers, err := e.Replace(2, []faults.Rule{outage}, nil)
		if err != nil {
			t.Fatal(err)
		}
		draw := func(choice string) time.Duration {
			return faults.Between(testSeed.Draw(faults.Key{Rule: "outage", Activation: 3, Choice: choice, Ordinal: 1}), someTime.Min, someTime.Max)
		}
		if len(timers) != 1 {
			t.Fatalf("Replace returned timers %+v, want the outage's", timers)
		}
		down, _ := timers[0].Action.(sftpproxy.ListenerDown)
		if !timers[0].At.Equal(changed.Add(draw("at"))) || down.Duration != draw("duration") || !down.CloseExisting {
			t.Errorf("timer = %+v, want the outage %v after the change, for %v, drawn afresh", timers[0], draw("at"), draw("duration"))
		}
		if got := e.Counts()["outage"]; got != (faults.Counts{Matched: 1, Selected: 1}) {
			t.Errorf("counts = %+v, want the outage selected once since the change", got)
		}
		if !timers[0].Reserve() {
			t.Error("Reserve declined the outage of a current rule")
		}
	})
}

func TestARemovedRuleReleasesItsWaits(t *testing.T) {
	freeze := sftpproxy.Freeze{Limit: time.Minute}
	slow := faults.Rule{ID: "slow", Match: stat, Action: sftpproxy.Delay{Duration: time.Minute}}
	rules := []faults.Rule{
		slow,
		{ID: "frozen", Match: faults.Match{Operations: ops(faults.LStat)}, Action: freeze},
		{ID: "cut", Match: faults.Match{Operations: ops(faults.Write), Path: faults.Location{Kind: faults.Exactly, Pattern: "/f"}}, Action: sftpproxy.PartialUpload{Cutoff: 1, Result: freeze}},
		{ID: "slow-login", Match: faults.Match{Operations: ops(faults.Authenticate)}, Action: sftpproxy.Delay{Duration: time.Minute}},
		{ID: "frozen-in-the-run", Trigger: &faults.Trigger{Anchor: faults.Run, At: at(time.Hour)}, Action: freeze},
		{ID: "frozen-after-login", Trigger: &faults.Trigger{Anchor: faults.Connection, At: at(time.Hour)}, Action: freeze},
	}
	someTime := &faults.Range[time.Duration]{Min: time.Second, Max: time.Minute}
	rules = append(rules,
		faults.Rule{ID: "slow-mkdir", Match: faults.Match{Operations: ops(faults.Mkdir)}, Duration: someTime, Action: sftpproxy.Delay{}},
		faults.Rule{ID: "cut-somewhere", Match: faults.Match{Operations: ops(faults.Write), Path: faults.Location{Kind: faults.Exactly, Pattern: "/g"}}, Cutoff: &faults.Range[uint64]{Min: 1, Max: 9}, Action: sftpproxy.PartialUpload{Result: freeze}},
		faults.Rule{ID: "stuck", Match: faults.Match{Operations: ops(faults.Remove)}, Action: sftpproxy.Stall{When: sftpproxy.After, Limit: time.Minute}},
		faults.Rule{ID: "edited", Match: faults.Match{Operations: ops(faults.Rmdir)}, Action: sftpproxy.Delay{Duration: time.Minute}},
	)
	e := newEngine(t, rules...)
	s := e.Session(faults.Client{User: "test", Authenticated: time.Now()})
	defer s.End()
	decide := s.Decide
	kept := decide(on(&sftpwire.Stat{}, "/f")).(sftpproxy.Delay).Release
	timers := s.Timers()
	if len(timers) != 2 {
		t.Fatalf("session timers = %+v, want the freezes at a moment of the run and of the connection", timers)
	}
	waits := map[string]<-chan struct{}{
		"a freeze at a moment of the run":   timers[0].Action.(sftpproxy.Freeze).Release,
		"a freeze at a connection's moment": timers[1].Action.(sftpproxy.Freeze).Release,
		"a freeze":                          decide(on(&sftpwire.LStat{}, "/f")).(sftpproxy.Freeze).Release,
		"a partial upload's freeze":         decide(openFor("/f", sftpwire.OpenWrite)).(sftpproxy.PartialUpload).Result.(sftpproxy.Freeze).Release,
		"a login's delay":                   e.Authenticate(faults.Client{User: "test"}).(sftpproxy.Delay).Release,
		"a delay of a drawn duration":       decide(on(&sftpwire.Mkdir{}, "/d")).(sftpproxy.Delay).Release,
		"the freeze of a drawn cutoff":      decide(openFor("/g", sftpwire.OpenWrite)).(sftpproxy.PartialUpload).Result.(sftpproxy.Freeze).Release,
		"the delay of an edited rule":       decide(on(&sftpwire.Rmdir{}, "/d")).(sftpproxy.Delay).Release,
		"a stall":                           decide(on(&sftpwire.Remove{}, "/f")).(sftpproxy.Stall).Release,
	}
	edited := rules[len(rules)-1]
	edited.Action = sftpproxy.Delay{Duration: time.Hour}
	if _, err := e.Replace(1, []faults.Rule{slow, edited}, nil); err != nil {
		t.Fatal(err)
	}
	for name, release := range waits {
		select {
		case <-release:
		default:
			t.Errorf("%s of a removed rule was not released", name)
		}
	}
	select {
	case <-kept:
		t.Error("the delay of a rule that carries on was released")
	default:
	}
}

func TestTheMomentsOfARemovedRuleDoNotCome(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs bytes.Buffer
		rules := []faults.Rule{
			{ID: "outage", Trigger: &faults.Trigger{Anchor: faults.Run, At: at(time.Minute)}, Action: outage},
			{ID: "end", Trigger: &faults.Trigger{Anchor: faults.Connection, At: at(time.Minute)}, Action: sftpproxy.EndSession{}},
			{ID: "end-at-run", Trigger: &faults.Trigger{Anchor: faults.Run, At: at(time.Minute)}, Action: sftpproxy.EndSession{}},
			{ID: "timed", Match: faults.Match{Operations: ops(faults.Write), Path: faults.Location{Kind: faults.Exactly, Pattern: "/t"}}, Trigger: &faults.Trigger{Anchor: faults.Transfer, At: at(time.Minute)}, Action: sftpproxy.EndSession{}},
			{ID: "cut", Match: faults.Match{Operations: ops(faults.Write)}, Action: cutOff},
			{ID: "corrupt", Match: faults.Match{Operations: ops(faults.Read)}, Action: sftpproxy.CorruptDownload{Corruption: sftpproxy.Truncate}},
		}
		e, err := faults.New(rules, nil, testSeed, slog.New(slog.NewTextHandler(&logs, nil)))
		if err != nil {
			t.Fatal(err)
		}
		s := e.Session(faults.Client{User: "test", Connection: 1, Authenticated: time.Now()})
		defer s.End()
		timers := s.Timers()
		if len(timers) != 2 {
			t.Fatalf("session timers = %+v, want the connection's and the run's", timers)
		}
		moments := map[string]func() bool{
			"the run's outage":        e.Timers()[0].Reserve,
			"the connection's moment": timers[0].Reserve,
			"the run's moment":        timers[1].Reserve,
			"a transfer's moment":     s.Decide(openFor("/t", sftpwire.OpenWrite)).(sftpproxy.Timed).Reserve,
		}
		transfers := map[string]func() bool{
			"a partial upload":   s.Decide(openFor("/w", sftpwire.OpenWrite)).(sftpproxy.PartialUpload).Reserve,
			"a corrupt download": s.Decide(openFor("/r", sftpwire.OpenRead)).(sftpproxy.CorruptDownload).Reserve,
		}
		if _, err := e.Replace(1, nil, nil); err != nil {
			t.Fatal(err)
		}
		for name, reserve := range moments {
			if reserve() {
				t.Errorf("%s of a removed rule came", name)
			}
		}
		for name, reserve := range transfers {
			if !reserve() {
				t.Errorf("%s that a removed rule selected lost its fault", name)
			}
		}
		if want := `msg="rule suppressed" rule=outage anchor=run at=1m0s reason=removed`; !strings.Contains(logs.String(), want) {
			t.Errorf("logs lack %s:\n%s", want, logs.String())
		}
	})
}

func TestOpenSessionsAreTimedForRulesAddedLive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEngine(t)
		authenticated := time.Now()
		// Sessions start in another order than their connections came in.
		connections := []uint64{4, 2, 6, 1, 5, 3}
		sessions := make(map[uint64]*faults.Session)
		for _, conn := range connections {
			sessions[conn] = e.Session(faults.Client{User: "a", Connection: conn, Authenticated: authenticated})
		}
		other := e.Session(faults.Client{User: "b", Connection: 7, Authenticated: authenticated})
		ended := e.Session(faults.Client{User: "a", Connection: 8, Authenticated: authenticated})
		ended.End()
		ended.End()
		// pending ends before it takes its timers, which must not wait
		// for it then.
		pending := e.Session(faults.Client{User: "a", Connection: 10, Authenticated: authenticated})
		time.Sleep(time.Minute)

		someTime := faults.Range[time.Duration]{Min: time.Second, Max: time.Hour}
		rules := []faults.Rule{
			{ID: "per-connection", Match: faults.Match{User: "a"}, Trigger: &faults.Trigger{Anchor: faults.Connection, At: &someTime}, Action: sftpproxy.Drop{}},
			{ID: "soon", Trigger: &faults.Trigger{Anchor: faults.Run, At: at(5 * time.Second)}, Action: sftpproxy.EndSession{}},
		}
		if _, err := e.Replace(1, rules, nil); err != nil {
			t.Fatal(err)
		}
		changed := time.Now()
		pending.End()
		// receive returns the timers delivered to s, by their moment.
		receive := func(s *faults.Session) []sftpproxy.Timer {
			var timers []sftpproxy.Timer
			for {
				synctest.Wait()
				select {
				case timer := <-s.MoreTimers():
					timers = append(timers, timer)
				default:
					slices.SortFunc(timers, func(a, b sftpproxy.Timer) int { return a.At.Compare(b.At) })
					return timers
				}
			}
		}
		for i := range uint64(6) {
			conn := i + 1
			key := faults.Key{Rule: "per-connection", Activation: 2, Choice: "at", User: "a", Ordinal: conn}
			moment := authenticated.Add(faults.Between(testSeed.Draw(key), someTime.Min, someTime.Max))
			want := []sftpproxy.Timer{{At: changed.Add(5 * time.Second), Action: sftpproxy.EndSession{}}, {At: moment, Action: sftpproxy.Drop{}}}
			slices.SortFunc(want, func(a, b sftpproxy.Timer) int { return a.At.Compare(b.At) })
			got := receive(sessions[conn])
			if len(got) != 2 || got[0].At != want[0].At || got[1].At != want[1].At || got[0].Action != want[0].Action || got[1].Action != want[1].Action {
				t.Errorf("connection %d got timers %+v, want %+v, its moment drawn in the order the connections came", conn, got, want)
			}
		}
		if got := receive(other); len(got) != 1 || got[0].Action != (sftpproxy.EndSession{}) {
			t.Errorf("another user's session got timers %+v, want only the run's moment", got)
		}
		if got := receive(ended); len(got) != 0 {
			t.Errorf("an ended session got timers %+v", got)
		}
		late := e.Session(faults.Client{User: "a", Connection: 9, Authenticated: time.Now()})
		if got := late.Timers(); len(got) != 2 {
			t.Errorf("a session after the change got timers %+v, want both rules'", got)
		}
		counts := e.Counts()
		if want := (faults.Counts{Matched: 9, Selected: 9}); counts["soon"] != want {
			t.Errorf("soon counts = %+v, want %+v: every session that had not ended, and the late one", counts["soon"], want)
		}
		if want := (faults.Counts{Matched: 8, Selected: 8}); counts["per-connection"] != want {
			t.Errorf("per-connection counts = %+v, want %+v: a's connections that had not ended, and the late one", counts["per-connection"], want)
		}
		for _, s := range sessions {
			s.End()
		}
		other.End()
		late.End()
	})
}
