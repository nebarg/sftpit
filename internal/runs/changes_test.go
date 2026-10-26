package runs

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
)

func TestRulesChangeDuringARun(t *testing.T) {
	m, addr := startManager(t, Options{})
	run := m.Status().Run.ID
	c, _ := dialSFTP(t, addr)
	if _, err := c.Stat("/"); err != nil {
		t.Fatalf("a stat before the change = %v", err)
	}

	set, err := m.ChangeRules(run, 1, []faults.Rule{denyStats}, nil)
	if err != nil {
		t.Fatalf("ChangeRules: %v", err)
	}
	if set.Revision != 2 || len(set.Rules) != 1 || set.Rules[0].ID != "deny-stats" {
		t.Errorf("ChangeRules = %+v, want revision 2 with deny-stats", set)
	}
	if got, err := m.Rules(run); err != nil || got.Revision != 2 || len(got.Rules) != 1 {
		t.Errorf("Rules = %+v, %v; want the changed rules", got, err)
	}
	if s := m.Status(); s.Revision != 2 {
		t.Errorf("the status has revision %d, want 2", s.Revision)
	}
	if _, err := c.Stat("/"); !errors.Is(err, os.ErrPermission) {
		t.Errorf("a stat after the change = %v, want it denied on the session already open", err)
	}

	if _, err := m.ChangeRules(run, 1, nil, nil); !errors.Is(err, faults.ErrStaleRevision) {
		t.Errorf("a change from revision 1 = %v, want ErrStaleRevision", err)
	}
	if _, err := m.ChangeRules("20261024-101500.123-3f9a", 2, nil, nil); !errors.Is(err, ErrStaleRun) {
		t.Errorf("a change to another run = %v, want ErrStaleRun", err)
	}
	if _, err := m.Rules("20261024-101500.123-3f9a"); !errors.Is(err, ErrStaleRun) {
		t.Errorf("the rules of another run = %v, want ErrStaleRun", err)
	}

	if _, err := m.Reset(t.Context(), ResetRequest{}); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if s := m.Status(); s.Revision != 1 {
		t.Errorf("after a reset, the status has revision %d, want the next run's first", s.Revision)
	}
	c, _ = dialSFTP(t, addr)
	if _, err := c.Stat("/"); err != nil {
		t.Errorf("after a reset, a stat = %v, want the scenario's rules, which are none", err)
	}
}

func TestARemovedRuleReleasesAConnectionItHolds(t *testing.T) {
	tests := []struct {
		name   string
		action sftpproxy.Action
		// banner is set if the client gets the server's banner once the
		// fault is released, and otherwise its connection is closed.
		banner bool
	}{
		{"delay", sftpproxy.Delay{Duration: time.Minute}, true},
		{"freeze", sftpproxy.Freeze{Limit: time.Minute}, false},
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
			if _, err := m.ChangeRules(m.Status().Run.ID, 1, nil, nil); err != nil {
				t.Fatalf("ChangeRules: %v", err)
			}
			if err := raw.SetDeadline(time.Now().Add(waitTimeout)); err != nil {
				t.Fatal(err)
			}
			line, err := bufio.NewReader(raw).ReadString('\n')
			switch {
			case tt.banner && !strings.HasPrefix(line, "SSH-2.0-"):
				t.Errorf("read %q (%v), want the server's banner once the delay is released", line, err)
			case !tt.banner && (line != "" || !errors.Is(err, io.EOF)):
				t.Errorf("read %q (%v), want the frozen connection closed once it is released", line, err)
			}
			awaitLog(t, logs, "fault released")
		})
	}
}

func TestALiveRuleTakesTheServerDownAtItsMoment(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := newManager(t, Options{})
		run := m.Status().Run.ID
		// A moment that a change removes before it comes never comes.
		if _, err := m.ChangeRules(run, 1, []faults.Rule{outageAt(300 * time.Millisecond)}, nil); err != nil {
			t.Fatalf("ChangeRules: %v", err)
		}
		if _, err := m.ChangeRules(run, 2, nil, nil); err != nil {
			t.Fatalf("ChangeRules: %v", err)
		}
		time.Sleep(time.Hour)
		if s := m.Status(); s.State != StateUp {
			t.Errorf("the status is %+v, want the server up once the outage's rule is removed", s)
		}

		if _, err := m.ChangeRules(run, 3, []faults.Rule{outageAt(300 * time.Millisecond)}, nil); err != nil {
			t.Fatalf("ChangeRules: %v", err)
		}
		time.Sleep(300*time.Millisecond - time.Nanosecond)
		synctest.Wait()
		if s := m.Status(); s.State != StateUp {
			t.Errorf("just before 300ms after the change, the status is %+v, want up", s)
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if s := m.Status(); s.State != StateDown {
			t.Errorf("300ms after the change, the status is %+v, want down", s)
		}
	})
}

func TestResetStopsTheTimersOfLiveRules(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := newManager(t, Options{})
		if _, err := m.ChangeRules(m.Status().Run.ID, 1, []faults.Rule{outageAt(300 * time.Millisecond)}, nil); err != nil {
			t.Fatalf("ChangeRules: %v", err)
		}
		if _, err := m.Reset(t.Context(), ResetRequest{}); err != nil {
			t.Fatalf("Reset: %v", err)
		}
		time.Sleep(time.Hour)
		if s := m.Status(); s.State != StateUp {
			t.Errorf("the status is %+v, want the next run, which has no faults, up", s)
		}
	})
}

func TestALiveRuleIsNotTimedForSessionsThatHaveEnded(t *testing.T) {
	m, addr := startManager(t, Options{})
	run := m.Status().Run.ID
	c, _ := dialSFTP(t, addr)
	if _, err := c.Stat("/"); err != nil {
		t.Fatalf("Stat: %v", err)
	}
	c.Close()
	moment := &faults.Range[time.Duration]{Min: time.Hour, Max: time.Hour}
	// The server ends the session soon after the client has gone, and the
	// rule then matches no session.
	deadline := time.Now().Add(waitTimeout)
	for revision := uint64(1); ; revision++ {
		later := faults.Rule{ID: fmt.Sprintf("later-%d", revision), Trigger: &faults.Trigger{Anchor: faults.Run, At: moment}, Action: sftpproxy.EndSession{}}
		set, err := m.ChangeRules(run, revision, []faults.Rule{later}, nil)
		if err != nil {
			t.Fatalf("ChangeRules: %v", err)
		}
		if set.Counts[later.ID].Matched == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a rule added after the only session ended matched it: %+v", set.Counts)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestALiveRuleClosesConnectionsAlreadyOpenAtItsMoment(t *testing.T) {
	m, addr := startManager(t, Options{})
	c, ended := dialSFTP(t, addr)
	if _, err := c.Stat("/"); err != nil {
		t.Fatalf("Stat: %v", err)
	}
	moment := &faults.Range[time.Duration]{Min: 100 * time.Millisecond, Max: 100 * time.Millisecond}
	hangUp := faults.Rule{ID: "hang-up", Trigger: &faults.Trigger{Anchor: faults.Run, At: moment}, Action: sftpproxy.Drop{}}
	if _, err := m.ChangeRules(m.Status().Run.ID, 1, []faults.Rule{hangUp}, nil); err != nil {
		t.Fatalf("ChangeRules: %v", err)
	}
	receive(t, ended)
	if got := m.Status(); got.State != StateUp {
		t.Errorf("the status is %+v, want the server still up", got)
	}
}
