package runs

import (
	"bufio"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
)

func TestReleaseStallsLetsAStalledRequestGoOn(t *testing.T) {
	stuck := faults.Rule{ID: "stuck", Match: faults.Match{Operations: []faults.Operation{faults.Stat}}, Action: sftpproxy.Stall{When: sftpproxy.Before, Limit: time.Minute}}
	m, addr := startManager(t, Options{Scenarios: map[string]config.Scenario{"stuck": {Rules: []faults.Rule{stuck}}}, Scenario: "stuck"})
	run := m.Status().Run.ID
	c, _ := dialSFTP(t, addr)
	for stat := 1; stat <= 2; stat++ {
		done := make(chan error, 1)
		go func() {
			_, err := c.Stat("/")
			done <- err
		}()
		awaitFired(t, m, "stuck", uint64(stat))
		select {
		case err := <-done:
			t.Fatalf("stat %d returned %v before the release", stat, err)
		case <-time.After(100 * time.Millisecond):
		}
		if err := m.ReleaseStalls(run); err != nil {
			t.Fatalf("ReleaseStalls: %v", err)
		}
		if err := receive(t, done); err != nil {
			t.Errorf("stat %d after the release = %v", stat, err)
		}
	}
	if err := m.ReleaseStalls("20261024-101500.123-3f9a"); !errors.Is(err, ErrStaleRun) {
		t.Errorf("ReleaseStalls of another run = %v, want ErrStaleRun", err)
	}
}

func TestReleaseStallsClosesAConnectionFrozenAtConnectButLeavesADelay(t *testing.T) {
	tests := []struct {
		name   string
		action sftpproxy.Action
		// closed is set if the release closes the connection, and
		// otherwise the client sees nothing yet.
		closed bool
	}{
		{"freeze", sftpproxy.Freeze{Limit: time.Minute}, true},
		{"delay", sftpproxy.Delay{Duration: time.Minute}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := make(messages, 64)
			held := connectRule(tt.action)
			m, addr := startManager(t, Options{Scenarios: map[string]config.Scenario{"held": {Rules: []faults.Rule{held}}}, Scenario: "held", Logger: slog.New(logs)})
			raw, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer raw.Close()
			awaitLog(t, logs, "injected fault")
			if err := m.ReleaseStalls(m.Status().Run.ID); err != nil {
				t.Fatalf("ReleaseStalls: %v", err)
			}
			wait := waitTimeout
			if !tt.closed {
				wait = 300 * time.Millisecond
			}
			if err := raw.SetDeadline(time.Now().Add(wait)); err != nil {
				t.Fatal(err)
			}
			line, err := bufio.NewReader(raw).ReadString('\n')
			switch {
			case tt.closed && (line != "" || !errors.Is(err, io.EOF)):
				t.Errorf("read %q (%v), want the frozen connection closed once released", line, err)
			case !tt.closed && !errors.Is(err, os.ErrDeadlineExceeded):
				t.Errorf("read %q (%v), want the delay to go on", line, err)
			}
			if tt.closed {
				awaitLog(t, logs, "fault released")
			}
		})
	}
}

func TestResetStartsAnInlineScenario(t *testing.T) {
	var logs syncBuffer
	m, addr := startManager(t, Options{Scenarios: map[string]config.Scenario{"chaos": {}}, Scenario: "chaos", Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	inline := &InlineScenario{Rules: []faults.Rule{denyStats}}
	status, err := m.Reset(t.Context(), ResetRequest{Inline: inline, Seed: new(faults.Seed(7))})
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if want := (Scenario{Inline: true, Seed: 7, Pinned: true}); status.Run.Scenario != want {
		t.Errorf("the run's scenario is %+v, want %+v", status.Run.Scenario, want)
	}
	if want := "msg=reset run=" + status.Run.ID + " inline=true seed=7 seed_pinned=true"; !strings.Contains(logs.String(), want) {
		t.Errorf("logs lack %s:\n%s", want, logs.String())
	}
	c, _ := dialSFTP(t, addr)
	if _, err := c.Stat("/"); !errors.Is(err, os.ErrPermission) {
		t.Errorf("a stat = %v, want it denied by the inline rule", err)
	}

	// A bare reset repeats the inline scenario, with its pinned seed, and
	// not the rules the run had come to.
	if _, err := m.ChangeRules(status.Run.ID, 1, nil, nil); err != nil {
		t.Fatalf("ChangeRules: %v", err)
	}
	status, err = m.Reset(t.Context(), ResetRequest{})
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
	set, err := m.Rules(status.Run.ID)
	if want := (Scenario{Inline: true, Seed: 7, Pinned: true}); err != nil || status.Run.Scenario != want || len(set.Rules) != 1 || set.Rules[0].ID != "deny-stats" {
		t.Errorf("after a bare reset, the run has %+v and rules %+v (%v), want the inline scenario again", status.Run.Scenario, set, err)
	}
	status, err = m.Reset(t.Context(), ResetRequest{Inline: inline})
	if err != nil || !status.Run.Scenario.Inline || status.Run.Scenario.Pinned {
		t.Errorf("an inline reset without a seed started %+v (%v), want a fresh seed", status, err)
	}

	tests := []struct {
		name string
		req  ResetRequest
		want error
	}{
		{"a named and an inline scenario", ResetRequest{Scenario: new("chaos"), Inline: inline}, ErrTwoScenarios},
		{"rules an engine cannot apply", ResetRequest{Inline: &InlineScenario{Rules: []faults.Rule{denyStats, denyStats}}}, nil},
		{"chaos an engine cannot apply", ResetRequest{Inline: &InlineScenario{Chaos: &faults.Chaos{Preset: "wild"}}}, nil},
	}
	for _, tt := range tests {
		before := m.Status().Run.ID
		_, err := m.Reset(t.Context(), tt.req)
		if err == nil || (tt.want != nil && !errors.Is(err, tt.want)) {
			t.Errorf("a reset with %s = %v, want it refused", tt.name, err)
		}
		if s := m.Status(); s.Run.ID != before || s.State != StateUp {
			t.Errorf("a reset with %s left the status %+v, want the run alone", tt.name, s)
		}
	}
}

// awaitFired waits until the current run's rule id has fired n times.
func awaitFired(t *testing.T, m *Manager, id string, n uint64) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		set, err := m.Rules(m.Status().Run.ID)
		if err != nil {
			t.Fatalf("Rules: %v", err)
		}
		if set.Counts[id].Fired >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("rule %s has fired %d times, want %d", id, set.Counts[id].Fired, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
