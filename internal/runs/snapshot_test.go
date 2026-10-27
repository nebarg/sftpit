package runs

import (
	"bytes"
	"crypto/sha256"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/backend"
)

func TestSnapshotsCopyFilesWithinTheBudget(t *testing.T) {
	w, err := OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	run, err := w.NewRun(Scenario{})
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"In/Orders.csv": strings.Repeat("o", 10),
		"big.bin":       strings.Repeat("b", 30),
		"small.txt":     strings.Repeat("s", 5),
	}
	seed := t.TempDir()
	for name, content := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(seed, name)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(seed, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(run.Files)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	limits := backend.Limits{MaxFileBytes: 100, MaxTotalBytes: 100, MaxFiles: 10, MaxOpenFiles: 10}
	embedded, err := backend.New(root, backend.Options{Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	if err := embedded.Seed(seed); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	s := &snapshots{run: run, embedded: embedded, logger: slog.New(slog.NewTextHandler(&logs, nil)), budget: 15}

	steps := []struct {
		name string
		// copy is where the copy goes, or "" for one past the budget.
		copy string
	}{
		{name: "In/Orders.csv", copy: "snapshots/1/^in/^orders.csv"},
		{name: "big.bin"},
		// This copy takes the run's copies exactly to their budget.
		{name: "small.txt", copy: "snapshots/2/small.txt"},
		{name: "In/Orders.csv"},
	}
	for _, step := range steps {
		content := files[step.name]
		snap, err := s.take("/" + step.name)
		if err != nil {
			t.Fatalf("take %s: %v", step.name, err)
		}
		if snap.Size != int64(len(content)) || snap.SHA256 != sha256.Sum256([]byte(content)) || snap.Copy != step.copy {
			t.Errorf("snapshot of %s = %d %x copied to %q, want %d %x copied to %q",
				step.name, snap.Size, snap.SHA256, snap.Copy, len(content), sha256.Sum256([]byte(content)), step.copy)
		}
		if step.copy != "" {
			if copied, err := os.ReadFile(filepath.Join(run.Dir, filepath.FromSlash(step.copy))); err != nil || string(copied) != content {
				t.Errorf("copy of %s = %q, %v; want the file", step.name, copied, err)
			}
		}
	}
	want := `level=INFO msg="snapshot not copied" path=/big.bin size=30 reason="the run's copies would exceed 15 bytes"`
	if got := strings.Count(logs.String(), "snapshot not copied"); got != 2 || !strings.Contains(logs.String(), want) {
		t.Errorf("log has %d skipped copies, want 2, including %q:\n%s", got, want, logs.String())
	}

	if _, err := s.take("/missing.csv"); err == nil {
		t.Error("a snapshot of a missing file succeeded")
	}
}

// A copy that fails keeps nothing, so it must not use up the budget.
func TestSnapshotsReturnTheBudgetOfACopyThatFails(t *testing.T) {
	w, err := OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	run, err := w.NewRun(Scenario{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(run.Files, "orders.csv"), []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(run.Files)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	limits := backend.Limits{MaxFileBytes: 100, MaxTotalBytes: 100, MaxFiles: 10, MaxOpenFiles: 10}
	embedded, err := backend.New(root, backend.Options{Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	s := &snapshots{run: run, embedded: embedded, logger: slog.New(slog.DiscardHandler), budget: 10}

	// A file where the copies' directory belongs makes the copy fail.
	blocker := filepath.Join(run.Dir, "snapshots")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.take("/orders.csv"); err == nil {
		t.Fatal("a snapshot whose copy failed succeeded")
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	snap, err := s.take("/orders.csv")
	if err != nil {
		t.Fatal(err)
	}
	if snap.Copy == "" {
		t.Error("the next snapshot was not copied, as if the failed copy had used the budget")
	}
}
