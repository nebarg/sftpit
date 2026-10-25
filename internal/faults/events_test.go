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

var (
	slowLogin = sftpproxy.Delay{When: sftpproxy.Before, Duration: 3 * time.Second}
	hangUp    = sftpproxy.Drop{When: sftpproxy.Before}
)

func TestConnectionEventsMatchTheirOwnRules(t *testing.T) {
	var logs bytes.Buffer
	e, err := faults.New([]faults.Rule{
		{ID: "second-connect", Match: faults.Match{Operations: ops(faults.Connect), Occurrence: []uint64{2}}, Action: slowLogin},
		{ID: "partner-login", MaxTriggers: 1, Match: faults.Match{Operations: ops(faults.Authenticate), KeyFingerprint: "SHA256:partner"}, Action: hangUp},
		{ID: "every-request", Match: faults.Match{Operations: ops(faults.Any)}, Action: failure},
	}, nil, testSeed, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	partner := faults.Client{User: "test", KeyFingerprint: "SHA256:partner", Connection: 2}

	if got := e.Connect(faults.Client{Connection: 1}); got != nil {
		t.Errorf("the first connect got %#v, want nothing", got)
	}
	if got := e.Connect(faults.Client{Connection: 2}); unreleased(got) != slowLogin {
		t.Errorf("the second connect got %#v, want %#v", got, slowLogin)
	}
	if got := e.Authenticate(faults.Client{User: "test", Connection: 1}); got != nil {
		t.Errorf("a password login got %#v, want nothing", got)
	}
	if got := e.Authenticate(partner); got != hangUp {
		t.Errorf("the partner's login got %#v, want %#v", got, hangUp)
	}
	if got := e.Authenticate(partner); got != nil {
		t.Errorf("the partner's second login got %#v, want nothing once max_triggers is used up", got)
	}
	if got := e.Session(partner).Decide(on(&sftpwire.Stat{}, "/f")); got != failure {
		t.Errorf("a stat got %#v, want the rule for every request", got)
	}

	want := map[string]faults.Counts{
		"second-connect": {Matched: 2, Selected: 1, Fired: 1},
		"partner-login":  {Matched: 2, Selected: 1, Fired: 1},
		"every-request":  {Matched: 1, Selected: 1, Fired: 1},
	}
	for id, counts := range e.Counts() {
		if counts != want[id] {
			t.Errorf("rule %s counts = %+v, want %+v", id, counts, want[id])
		}
	}
	for _, line := range []string{
		"rule fired\" rule=second-connect request=connect ordinal=2\n",
		"rule fired\" rule=partner-login request=authenticate user=test ordinal=1\n",
	} {
		if !strings.Contains(logs.String(), line) {
			t.Errorf("logs lack %q:\n%s", line, logs.String())
		}
	}
}

func TestConnectionEventsDrawTheirDecisions(t *testing.T) {
	rule := faults.Rule{
		ID:          "slow-login",
		Match:       faults.Match{Operations: ops(faults.Authenticate)},
		Probability: new(0.5),
		Duration:    &faults.Range[time.Duration]{Min: time.Second, Max: 10 * time.Second},
		Action:      sftpproxy.Delay{When: sftpproxy.Before},
	}
	logins := func() []sftpproxy.Action {
		e := newEngine(t, rule)
		var actions []sftpproxy.Action
		for range 20 {
			actions = append(actions, e.Authenticate(faults.Client{User: "test"}))
		}
		return actions
	}
	first, again := logins(), logins()
	var delayed int
	for i, a := range first {
		if unreleased(a) != unreleased(again[i]) {
			t.Errorf("login %d got %#v, then %#v from the same seed", i+1, a, again[i])
		}
		if d, ok := a.(sftpproxy.Delay); ok {
			delayed++
			if d.Duration < time.Second || d.Duration > 10*time.Second {
				t.Errorf("login %d was delayed %v, want 1s to 10s", i+1, d.Duration)
			}
		}
	}
	if delayed == 0 || delayed == len(first) {
		t.Errorf("%d of %d logins were delayed, want some but not all at a probability of 0.5", delayed, len(first))
	}
}

func TestConnectionEventsAreTimedFromTheRun(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEngine(t,
			faults.Rule{ID: "outage", Match: faults.Match{Operations: ops(faults.Connect)}, Trigger: &faults.Trigger{Anchor: faults.Run, Window: &faults.Window{From: 10 * time.Second, Until: 15 * time.Second}}, Action: hangUp},
			faults.Rule{ID: "late-login", Match: faults.Match{Operations: ops(faults.Authenticate)}, Trigger: &faults.Trigger{Anchor: faults.Run, At: at(12 * time.Second)}, Action: slowLogin},
		)
		for _, step := range []struct {
			sleep          time.Duration
			connect, login sftpproxy.Action
		}{
			{9 * time.Second, nil, nil},
			{time.Second, hangUp, nil},
			{2 * time.Second, hangUp, slowLogin},
			{time.Second, hangUp, nil},
			{2 * time.Second, nil, nil},
		} {
			time.Sleep(step.sleep)
			if got := e.Connect(faults.Client{}); got != step.connect {
				t.Errorf("a connect got %#v, want %#v", got, step.connect)
			}
			if got := e.Authenticate(faults.Client{User: "test"}); unreleased(got) != step.login {
				t.Errorf("a login got %#v, want %#v", got, step.login)
			}
		}
	})
}

func TestRulesForConnectionEventsThatCannotApplyAreRefused(t *testing.T) {
	connect := faults.Match{Operations: ops(faults.Connect)}
	login := faults.Match{Operations: ops(faults.Authenticate)}
	tests := []struct {
		name string
		rule faults.Rule
		err  string
	}{
		{"file operations", faults.Rule{Match: faults.Match{Operations: ops(faults.Authenticate, faults.OpenWrite)}, Action: hangUp}, "connect and authenticate cannot share a rule with file operations"},
		{"a path", faults.Rule{Match: faults.Match{Operations: ops(faults.Authenticate), Path: faults.Location{Kind: faults.Under, Pattern: "/in"}}, Action: hangUp}, "connect and authenticate have no path"},
		{"a user at connect", faults.Rule{Match: faults.Match{Operations: ops(faults.Connect, faults.Authenticate), User: "test"}, Action: hangUp}, "connect comes before the client logs in"},
		{"a key at connect", faults.Rule{Match: faults.Match{Operations: ops(faults.Connect), KeyFingerprint: "SHA256:k"}, Action: hangUp}, "connect comes before the client logs in"},
		{"a failure", faults.Rule{Match: login, Action: failure}, "connect and authenticate take a delay, close_connection, freeze_connection or listener_down, not sftpproxy.Fail"},
		{"an end of session", faults.Rule{Match: connect, Action: sftpproxy.EndSession{}}, "not sftpproxy.EndSession"},
		{"a stall", faults.Rule{Match: login, Action: sftpproxy.Stall{Limit: time.Second}}, "not sftpproxy.Stall"},
		{"attempts", faults.Rule{Match: faults.Match{Operations: ops(faults.Authenticate), Attempt: &faults.Attempt{Numbers: []uint64{1}}}, Action: hangUp}, "attempts count opens"},
		{"a connection's window", faults.Rule{Match: login, Trigger: &faults.Trigger{Anchor: faults.Connection, Window: &faults.Window{Until: time.Second}}, Action: slowLogin}, "connect and authenticate are timed from the run, not the connection"},
		{"a transfer's moment", faults.Rule{Match: connect, Trigger: &faults.Trigger{Anchor: faults.Transfer, At: at(time.Second)}, Action: hangUp}, "connect and authenticate are timed from the run, not the transfer"},
		{"a connection action at a moment", faults.Rule{Match: login, Trigger: &faults.Trigger{Anchor: faults.Run, At: at(time.Second)}, Action: hangUp}, "a connection action at a moment of the run matches only the user and key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.rule.ID = "r"
			_, err := faults.New([]faults.Rule{tt.rule}, nil, testSeed, nil)
			if err == nil || !strings.Contains(err.Error(), tt.err) {
				t.Errorf("New = %v, want an error about %q", err, tt.err)
			}
		})
	}
}
