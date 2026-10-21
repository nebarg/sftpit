package runs_test

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/runs"
)

func TestOpenWorkspaceMakesAMissingOrEmptyDirectoryAWorkspace(t *testing.T) {
	interrupted := t.TempDir()
	// A start interrupted before marking the directory leaves its lock file.
	writeFile(t, filepath.Join(interrupted, "workspace.lock"), "")
	dirs := map[string]string{
		"missing":     filepath.Join(t.TempDir(), "a", "sandbox-data"),
		"empty":       t.TempDir(),
		"interrupted": interrupted,
	}
	for name, dir := range dirs {
		t.Run(name, func(t *testing.T) {
			w := openWorkspace(t, dir)
			closeWorkspace(t, w)

			var m map[string]any
			b, err := os.ReadFile(filepath.Join(dir, "workspace.json"))
			if err != nil || json.Unmarshal(b, &m) != nil || m["owner"] != "sftpit" || m["version"] != 1.0 {
				t.Errorf("workspace.json = %s (%v), want the sftpit marker", b, err)
			}
			closeWorkspace(t, openWorkspace(t, dir))
		})
	}
}

func TestOpenWorkspaceRefusesOtherDirectories(t *testing.T) {
	tests := []struct {
		name   string
		file   string
		marker string
		want   string
	}{
		{name: "files and no marker", file: "notes.txt", want: "is not empty"},
		{name: "another tool's marker", marker: `{"owner": "other", "version": 1}`, want: "that sftpit did not write"},
		{name: "a broken marker", marker: `{"owner": "sftpit"`, want: "that sftpit did not write"},
		{name: "a newer layout", marker: `{"owner": "sftpit", "version": 2}`, want: "made by a newer sftpit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.file != "" {
				writeFile(t, filepath.Join(dir, tt.file), "keep me")
			}
			if tt.marker != "" {
				writeFile(t, filepath.Join(dir, "workspace.json"), tt.marker)
			}
			before := listDir(t, dir)

			w, err := runs.OpenWorkspace(dir)
			if !errors.Is(err, runs.ErrNotWorkspace) || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("OpenWorkspace = %v, want ErrNotWorkspace saying %q", err, tt.want)
			}
			if err == nil {
				w.Close()
			}
			if after := listDir(t, dir); !slices.Equal(after, before) {
				t.Errorf("the directory changed from %v to %v", before, after)
			}
		})
	}
}

func TestAWorkspaceHasOneUserAtATime(t *testing.T) {
	dir := t.TempDir()
	w := openWorkspace(t, dir)
	if second, err := runs.OpenWorkspace(dir); !errors.Is(err, runs.ErrInUse) {
		t.Errorf("a second OpenWorkspace = %v, want ErrInUse", err)
		if err == nil {
			second.Close()
		}
	}
	closeWorkspace(t, w)
	closeWorkspace(t, openWorkspace(t, dir))
}

func TestTempWorkspaceIsDeletedOnClose(t *testing.T) {
	w, err := runs.TempWorkspace()
	if err != nil {
		t.Fatalf("TempWorkspace: %v", err)
	}
	if !w.Temporary() {
		t.Error("Temporary() = false for a temporary workspace")
	}
	if _, err := w.NewRun(); err != nil {
		t.Fatalf("NewRun: %v", err)
	}
	closeWorkspace(t, w)
	if _, err := os.Stat(w.Dir()); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("workspace %s still exists after Close (%v)", w.Dir(), err)
	}
}

func TestNewRunKeepsTheNewestFiveRuns(t *testing.T) {
	dir := t.TempDir()
	w := openWorkspace(t, dir)
	defer closeWorkspace(t, w)
	// Entries that NewRun did not make are not runs, so they stay.
	others := []string{"notes.txt", "20260101-000000.000-zzzz"}
	if err := os.MkdirAll(filepath.Join(dir, "runs", others[1]), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "runs", others[0]), "keep me")

	idPattern := regexp.MustCompile(`^\d{8}-\d{6}\.\d{3}-[0-9a-f]{4}$`)
	var ids []string
	for range 7 {
		// Runs started in the same millisecond have no order.
		time.Sleep(2 * time.Millisecond)
		r, err := w.NewRun()
		if err != nil {
			t.Fatalf("NewRun: %v", err)
		}
		if !idPattern.MatchString(r.ID) || (len(ids) > 0 && r.ID <= ids[len(ids)-1]) {
			t.Errorf("run ID %q after %v, want a later ID like 20261021-131144.123-3f9a", r.ID, ids)
		}
		if r.Dir != filepath.Join(dir, "runs", r.ID) || r.Files != filepath.Join(r.Dir, "fs") {
			t.Errorf("run %s has Dir %s and Files %s", r.ID, r.Dir, r.Files)
		}
		if info, err := os.Stat(r.Files); err != nil || !info.IsDir() {
			t.Errorf("run %s has no files directory: %v", r.ID, err)
		}
		var record struct {
			ID      string    `json:"id"`
			Started time.Time `json:"started"`
		}
		b, err := os.ReadFile(filepath.Join(r.Dir, "run.json"))
		if err != nil || json.Unmarshal(b, &record) != nil || record.ID != r.ID || time.Since(record.Started) > time.Minute {
			t.Errorf("run.json = %s (%v), want the run's ID and start", b, err)
		}
		ids = append(ids, r.ID)
	}

	want := slices.Sorted(slices.Values(append(others, ids[2:]...)))
	if got := listDir(t, filepath.Join(dir, "runs")); !slices.Equal(got, want) {
		t.Errorf("runs/ holds %v, want the newest five runs and the other entries, %v", got, want)
	}
}

func openWorkspace(t *testing.T, dir string) *runs.Workspace {
	t.Helper()
	w, err := runs.OpenWorkspace(dir)
	if err != nil {
		t.Fatalf("OpenWorkspace: %v", err)
	}
	return w
}

func closeWorkspace(t *testing.T, w *runs.Workspace) {
	t.Helper()
	if err := w.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func writeFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
