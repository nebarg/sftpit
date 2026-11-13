package runs

import (
	"net"
	"slices"
	"testing"
	"time"

	"github.com/pkg/sftp"

	"github.com/nebarg/sftpit/internal/events"
	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

func TestEachRunRecordsItsEvents(t *testing.T) {
	deny := faults.Rule{ID: "deny", Match: faults.Match{Operations: []faults.Operation{faults.Stat}}, Action: sftpproxy.Fail{Status: sftpwire.StatusPermissionDenied}}
	m, addr := startManager(t, Options{})
	withRules(t, m, deny)
	first := m.Status().Run.ID
	rec := m.Events()
	conn := dialSSH(t, addr)
	c, err := sftp.NewClient(conn)
	if err != nil {
		t.Fatalf("sftp.NewClient: %v", err)
	}
	if _, err := c.Stat("/f"); err == nil {
		t.Error("Stat succeeded, want it denied")
	}
	c.Close()
	conn.Close()
	awaitEvent(t, rec, events.Disconnected)

	got := rec.Events().Events
	var kinds []events.Kind
	for _, e := range got {
		kinds = append(kinds, e.Kind)
	}
	want := []events.Kind{events.RunStarted, events.RulesChanged, events.Connected, events.Authenticated, events.FaultInjected, events.Operation, events.Disconnected}
	if !slices.Equal(kinds, want) {
		t.Fatalf("events are %v, want %v", kinds, want)
	}
	started := got[0]
	if r := started.Run; r == nil || r.ID != first || r.Seed == "" || started.Rules == nil || started.Rules.Revision != 1 {
		t.Errorf("run_started = %+v, want the run, its seed and its first revision", started)
	}
	if r := got[1].Rules; r == nil || r.Revision != 2 || r.Previous != 1 {
		t.Errorf("rules_changed = %+v, want revision 2, replacing 1", got[1])
	}
	id := got[2].Connection
	for _, e := range got[3:] {
		if e.Connection != id || e.User != testUser {
			t.Errorf("%s event of connection %d as %q, want %d as %q", e.Kind, e.Connection, e.User, id, testUser)
		}
	}
	if op := got[5]; op.Request != "SSH_FXP_STAT" || op.Path != "/f" || op.Reply != "SSH_FX_PERMISSION_DENIED" || op.Rule != "deny" {
		t.Errorf("operation = %+v, want the STAT denied by deny", op)
	}

	if _, err := changeRules(m, 2, nil); err != nil {
		t.Fatalf("changeRules: %v", err)
	}
	if got := rec.Events().Events; got[len(got)-1].Kind != events.RulesChanged || got[len(got)-1].Rules.Revision != 3 {
		t.Errorf("the last event is %+v, want rules_changed to revision 3", got[len(got)-1])
	}

	if _, err := m.Reset(t.Context()); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if e := m.Events().Events().Events; len(e) == 0 || e[0].Kind != events.RunStarted {
		t.Errorf("the next run's events begin with %+v, want run_started", e)
	}
}

func TestStatusCountsWaitsUntilTheyEnd(t *testing.T) {
	stuck := faults.Rule{ID: "stuck", Match: faults.Match{Operations: []faults.Operation{faults.Stat}}, Action: sftpproxy.Stall{When: sftpproxy.Before, Limit: time.Minute}}
	frozen := connectRule(sftpproxy.Freeze{Limit: time.Minute})
	m, addr := startManager(t, Options{})
	withRules(t, m, stuck, frozen)
	rec := m.Events()

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer raw.Close()
	awaitEvent(t, rec, events.FaultInjected)
	if s := m.Status(); s.Frozen != 1 || s.Stalled != 0 {
		t.Errorf("status with a frozen connection: %d stalled, %d frozen; want 0 and 1", s.Stalled, s.Frozen)
	}
	m.ReleaseStalls()
	if e := awaitEvent(t, rec, events.FaultEnded); e.Reason != "released" || e.Rule != frozen.ID {
		t.Errorf("fault_ended = %+v, want the freeze released", e)
	}

	// Without the freeze, a client can log in and stall.
	if _, err := changeRules(m, 2, []faults.Rule{stuck}); err != nil {
		t.Fatalf("changeRules: %v", err)
	}
	c, _ := dialSFTP(t, addr)
	go func() { _, _ = c.Stat("/") }()
	awaitFired(t, m, "stuck", 1)
	if s := m.Status(); s.Stalled != 1 || s.Frozen != 0 {
		t.Errorf("status with a stall: %d stalled, %d frozen; want 1 and 0", s.Stalled, s.Frozen)
	}
	if _, err := changeRules(m, 3, nil); err != nil {
		t.Fatalf("changeRules: %v", err)
	}
	deadline := time.Now().Add(waitTimeout)
	for !slices.ContainsFunc(rec.Events().Events, func(e events.Event) bool {
		return e.Kind == events.FaultEnded && e.Rule == stuck.ID && e.Reason == "canceled"
	}) {
		if time.Now().After(deadline) {
			t.Fatal("the stall's cancellation was not recorded")
		}
		time.Sleep(time.Millisecond)
	}
	if s := m.Status(); s.Stalled != 0 {
		t.Errorf("status after the stall's rule was removed: %d stalled, want 0", s.Stalled)
	}
}

// awaitEvent waits for rec's latest event of kind, which must come within
// waitTimeout.
func awaitEvent(t *testing.T, rec *events.Recorder, kind events.Kind) events.Event {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		for _, e := range slices.Backward(rec.Events().Events) {
			if e.Kind == kind {
				return e
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s event", kind)
		}
		time.Sleep(time.Millisecond)
	}
}
