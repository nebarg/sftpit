package runs

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"slices"
	"testing"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/events"
	"github.com/nebarg/sftpit/internal/sshfront"
)

func TestEachRunWritesItsEventsToItsTrace(t *testing.T) {
	m, addr := startManager(t, Options{})
	first := m.Status().Run.ID
	rec, err := m.Events(first)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	conn := dialSSH(t, addr)
	c, err := sftp.NewClient(conn)
	if err != nil {
		t.Fatalf("sftp.NewClient: %v", err)
	}
	if _, err := c.Stat("/missing"); err == nil {
		t.Error("Stat of a missing file succeeded")
	}
	c.Close()
	conn.Close()
	awaitEvent(t, rec, events.Disconnected)

	want := kinds(rec.Events(0, 100, events.Filter{}).Events)
	if got := kinds(readTrace(t, m, first)); !slices.Equal(got, want) {
		t.Errorf("the trace holds %v, want the run's events, %v", got, want)
	}
	if s := m.Status().Trace; !s.Complete || s.Err != nil || s.Size == 0 {
		t.Errorf("the run's trace is %+v, want it complete", s)
	}

	if _, err := m.Reset(t.Context(), ResetRequest{}); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if got := kinds(readTrace(t, m, first)); !slices.Equal(got, want) {
		t.Errorf("after a reset, the ended run's trace holds %v, want %v", got, want)
	}
	if s := rec.Trace(); !s.Complete {
		t.Errorf("after a reset, the ended run's trace is %+v, want it complete", s)
	}
	if got := kinds(readTrace(t, m, m.Status().Run.ID)); !slices.Equal(got, []events.Kind{events.RunStarted}) {
		t.Errorf("the next run's trace holds %v, want only its start", got)
	}
	if _, _, err := m.OpenTrace("20260101-000000.000-0000"); !errors.Is(err, ErrUnknownRun) {
		t.Errorf("OpenTrace of an unknown run = %v, want %v", err, ErrUnknownRun)
	}
}

func TestATraceStopsAtItsBound(t *testing.T) {
	m, addr := startManager(t, Options{MaxTraceBytes: 512})
	rec, err := m.Events(m.Status().Run.ID)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	dialSSH(t, addr).Close()
	awaitEvent(t, rec, events.Disconnected)

	lines := readTrace(t, m, m.Status().Run.ID)
	last := lines[len(lines)-1]
	if last.Kind != events.TraceFull || last.ID != uint64(len(lines)) {
		t.Errorf("the trace ends with %+v, want trace_full naming event %d, the first left out", last, len(lines))
	}
	if s := m.Status().Trace; s.Complete || s.Err != nil {
		t.Errorf("the run's trace is %+v, want it incomplete, without an error", s)
	}
}

// A workspace kept with --data-dir holds the traces of runs that an earlier
// serve started.
func TestOpenTraceReadsARunOfAnEarlierManager(t *testing.T) {
	dir := t.TempDir()
	opts := Options{Server: sshfront.Config{HostKeys: []ssh.Signer{newHostKey(t)}, Users: []sshfront.User{{Name: testUser, Password: testPassword, Home: "/"}}}, Logger: slog.New(slog.DiscardHandler)}
	start := func() (*Workspace, *Manager) {
		w, err := OpenWorkspace(dir)
		if err != nil {
			t.Fatalf("OpenWorkspace: %v", err)
		}
		m, err := Start(w, opts)
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
		return w, m
	}
	w, m := start()
	earlier := m.Status().Run.ID
	m.Close()
	w.Close()

	w, m = start()
	defer w.Close()
	defer m.Close()
	if got := kinds(readTrace(t, m, earlier)); !slices.Equal(got, []events.Kind{events.RunStarted}) {
		t.Errorf("the earlier run's trace holds %v, want its start", got)
	}
}

func TestOpenTraceOfARunWithoutOne(t *testing.T) {
	m := newManager(t, Options{})
	run := m.Status().Run.ID
	if err := m.workspace.root.Remove("runs/" + run + "/" + traceFile); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.OpenTrace(run); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("OpenTrace of a run without a trace = %v, want %v", err, fs.ErrNotExist)
	}
}

// readTrace returns the events in the whole lines of run's trace.
func readTrace(t *testing.T, m *Manager, run string) []events.Event {
	t.Helper()
	f, size, err := m.OpenTrace(run)
	if err != nil {
		t.Fatalf("OpenTrace(%s): %v", run, err)
	}
	defer f.Close()
	var lines []events.Event
	s := bufio.NewScanner(io.NewSectionReader(f, 0, size))
	for s.Scan() {
		var e events.Event
		if err := json.Unmarshal(s.Bytes(), &e); err != nil {
			t.Fatalf("trace line %q: %v", s.Text(), err)
		}
		lines = append(lines, e)
	}
	return lines
}

func kinds(es []events.Event) []events.Kind {
	var got []events.Kind
	for _, e := range es {
		got = append(got, e.Kind)
	}
	return got
}
