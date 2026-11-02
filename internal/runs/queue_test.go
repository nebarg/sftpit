package runs

import (
	"errors"
	"testing"

	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

func TestTheNextBareResetStartsWithTheQueuedRules(t *testing.T) {
	m, _ := startManager(t, Options{Scenarios: map[string]config.Scenario{"chaos": {}}, Scenario: "chaos"})
	deny := faults.Rule{ID: "deny", Match: faults.Match{Operations: []faults.Operation{faults.Remove}}, Action: sftpproxy.Fail{When: sftpproxy.Before, Status: sftpwire.StatusFailure}}
	if err := m.Queue(&InlineScenario{Rules: []faults.Rule{deny}}); err != nil {
		t.Fatalf("Queue: %v", err)
	}
	if !m.Status().Queued || m.Queued() == nil {
		t.Fatalf("status = %+v, want the next run queued", m.Status())
	}

	if _, err := m.Reset(t.Context(), ResetRequest{Run: "20260101-000000.000-0000"}); !errors.Is(err, ErrStaleRun) {
		t.Fatalf("a stale reset = %v", err)
	}
	if !m.Status().Queued {
		t.Error("a refused reset cleared the queue")
	}

	next, err := m.Reset(t.Context(), ResetRequest{Seed: new(faults.Seed(3))})
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if got := next.Run.Scenario; got != (Scenario{Inline: true, Seed: 3, Pinned: true}) || next.Queued {
		t.Errorf("the next run is %+v, queued %v, want the queued rules inline, seed 3, and nothing queued", got, next.Queued)
	}
	if set, err := m.Rules(next.Run.ID); err != nil || len(set.Rules) != 1 || set.Rules[0].ID != "deny" {
		t.Errorf("the next run has rules %+v, %v, want deny", set.Rules, err)
	}
}

func TestAnyResetClearsTheQueue(t *testing.T) {
	m, _ := startManager(t, Options{Scenarios: map[string]config.Scenario{"chaos": {}}, Scenario: "chaos"})
	if err := m.Queue(&InlineScenario{}); err != nil {
		t.Fatalf("Queue: %v", err)
	}
	next, err := m.Reset(t.Context(), ResetRequest{Scenario: new("chaos")})
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if next.Run.Scenario.Name != "chaos" || next.Queued {
		t.Errorf("a reset that names a scenario started %+v, queued %v, want chaos and the queue cleared", next.Run.Scenario, next.Queued)
	}

	if err := m.Queue(&InlineScenario{}); err != nil {
		t.Fatalf("Queue: %v", err)
	}
	if err := m.Queue(nil); err != nil || m.Status().Queued {
		t.Errorf("Queue(nil) = %v, queued %v, want the queue cleared", err, m.Status().Queued)
	}
}

func TestQueueRefusesInvalidRules(t *testing.T) {
	m := newManager(t, Options{})
	rule := faults.Rule{ID: "twice", Match: faults.Match{Operations: []faults.Operation{faults.Stat}}, Action: sftpproxy.Hide{}}
	if err := m.Queue(&InlineScenario{Rules: []faults.Rule{rule, rule}}); err == nil || m.Status().Queued {
		t.Errorf("Queue of two rules with one ID = %v, queued %v, want it refused", err, m.Status().Queued)
	}
	if err := m.Queue(&InlineScenario{Chaos: &faults.Chaos{Preset: "wild"}}); err == nil || m.Status().Queued {
		t.Errorf("Queue of a bad preset = %v, want it refused", err)
	}
}
