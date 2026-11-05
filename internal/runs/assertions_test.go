package runs

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/testutil"
)

func TestExpectedFixturesAreSnapshottedOutOfClientsSight(t *testing.T) {
	expected := t.TempDir()
	testutil.WriteFile(t, filepath.Join(expected, "out", "orders.csv"), "id,total\n")
	m, addr := startManager(t, Options{ExpectedDir: expected})

	snapshot := filepath.Join(m.workspace.Dir(), filepath.FromSlash(expectedDir))
	got, err := os.ReadFile(filepath.Join(snapshot, "out", "orders.csv"))
	if err != nil || string(got) != "id,total\n" {
		t.Errorf("the snapshot holds %q, %v", got, err)
	}
	var recorded manifest
	data, err := os.ReadFile(filepath.Join(m.workspace.Dir(), filepath.FromSlash(expectedManifest)))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &recorded); err != nil {
		t.Fatal(err)
	}
	if recorded.Source != expected || len(recorded.Entries) != 2 || recorded.Entries[1].SHA256 == "" {
		t.Errorf("the manifest is %+v, want the directory and the file, with its hash", recorded)
	}

	// No client can reach them, however it asks.
	c, _ := dialSFTP(t, addr)
	walk := c.Walk("/")
	for walk.Step() {
		if err := walk.Err(); err != nil {
			t.Fatalf("Walk: %v", err)
		}
		if p := walk.Path(); strings.Contains(p, "orders") || strings.Contains(p, "expected") {
			t.Errorf("a client can see %s", p)
		}
	}
	for _, p := range []string{"/out/orders.csv", "/fixtures/expected/out/orders.csv", "/../../fixtures/expected/out/orders.csv"} {
		if _, err := c.Stat(p); err == nil {
			t.Errorf("a client can stat %s", p)
		}
	}

	// Later changes reach no assertion, and a reset leaves the snapshot alone.
	testutil.WriteFile(t, filepath.Join(expected, "out", "orders.csv"), "changed\n")
	if _, err := m.Reset(t.Context(), ResetRequest{}); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(snapshot, "out", "orders.csv")); err != nil || string(got) != "id,total\n" {
		t.Errorf("after a change and a reset, the snapshot holds %q, %v", got, err)
	}
	if err := m.expected.check(); err != nil {
		t.Errorf("the snapshot no longer matches its manifest: %v", err)
	}
}

func TestSnapshotExpectedRefusesTheWorkspaceAndRemovesAnOldSnapshot(t *testing.T) {
	parent := t.TempDir()
	w, err := OpenWorkspace(filepath.Join(parent, "ws"))
	if err != nil {
		t.Fatalf("OpenWorkspace: %v", err)
	}
	t.Cleanup(func() { w.Close() })
	expected := t.TempDir()
	testutil.WriteFile(t, filepath.Join(expected, "a.csv"), "a\n")
	snapshot, err := w.snapshotExpected(expected)
	if err != nil {
		t.Fatalf("snapshotExpected: %v", err)
	}
	for _, src := range []string{parent, w.Dir(), filepath.Join(w.Dir(), "fixtures"), filepath.Join(w.Dir(), "fixtures", "expected")} {
		if _, err := w.snapshotExpected(src); !errors.Is(err, ErrSeedOverlapsWorkspace) {
			t.Errorf("snapshotExpected(%s) = %v, want %v", src, err, ErrSeedOverlapsWorkspace)
		}
	}
	if err := snapshot.check(); err != nil {
		t.Errorf("the refused directories changed the snapshot: %v", err)
	}
	if s, err := w.snapshotExpected(""); s != nil || err != nil {
		t.Fatalf(`snapshotExpected("") = %+v, %v; want nothing`, s, err)
	}
	for _, gone := range []string{expectedDir, expectedManifest} {
		if _, err := os.Stat(filepath.Join(w.Dir(), filepath.FromSlash(gone))); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s after removing the snapshot: %v", gone, err)
		}
	}
}

func TestARunHasItsScenariosAssertions(t *testing.T) {
	absent := []config.Assertion{{Type: config.PathAbsent, Path: "/in/a.part"}}
	hashed := []config.Assertion{{Type: config.PathAbsent, Path: "/other"}}
	m, _ := startManager(t, Options{Scenarios: map[string]config.Scenario{"recovery": {Assertions: absent}, "plain": {}}, Scenario: "recovery"})
	assertRun := func(when string, want []config.Assertion) {
		t.Helper()
		got, err := m.Assertions(m.Status().Run.ID)
		if err != nil {
			t.Fatalf("%s: Assertions: %v", when, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: the run has assertions %+v, want %+v", when, got, want)
		}
	}
	assertRun("at the start", absent)
	first := m.Status().Run.ID

	reset := func(req ResetRequest) {
		t.Helper()
		if _, err := m.Reset(t.Context(), req); err != nil {
			t.Fatalf("Reset: %v", err)
		}
	}
	reset(ResetRequest{})
	assertRun("repeating the scenario", absent)
	if _, err := m.Assertions(first); !errors.Is(err, ErrStaleRun) {
		t.Errorf("Assertions of an ended run = %v, want %v", err, ErrStaleRun)
	}
	reset(ResetRequest{Scenario: new("plain")})
	assertRun("a scenario without any", nil)
	reset(ResetRequest{Inline: &InlineScenario{Assertions: hashed}})
	assertRun("inline", hashed)
	reset(ResetRequest{})
	assertRun("repeating the inline scenario", hashed)

	if err := m.Queue(&InlineScenario{Assertions: absent}); err != nil {
		t.Fatalf("Queue: %v", err)
	}
	assertRun("with a queue, until the reset", hashed)
	reset(ResetRequest{})
	assertRun("queued", absent)
	reset(ResetRequest{})
	assertRun("repeating what was queued", absent)
}

// A directory that does not exist yet must not be created by the snapshot
// and then copied into itself, for ever.
func TestASnapshotRefusesADirectoryThatDoesNotExist(t *testing.T) {
	w, err := OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatalf("OpenWorkspace: %v", err)
	}
	t.Cleanup(func() { w.Close() })
	for _, src := range []string{filepath.Join(w.Dir(), "fixtures"), filepath.Join(w.Dir(), "fixtures", "expected"), filepath.Join(w.Dir(), "fixtures", "seed"), filepath.Join(t.TempDir(), "missing")} {
		if _, err := w.snapshotExpected(src); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("snapshotExpected(%s) = %v, want %v", src, err, fs.ErrNotExist)
		}
		if _, err := w.snapshotSeed(src); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("snapshotSeed(%s) = %v, want %v", src, err, fs.ErrNotExist)
		}
	}
}
