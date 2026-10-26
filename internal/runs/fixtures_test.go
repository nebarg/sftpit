package runs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/backend"
)

func TestSnapshotSeedKeepsWhatEachRunStartsWith(t *testing.T) {
	stamp := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	seed := t.TempDir()
	makeSeed(t, seed, map[string]string{"outgoing/orders.csv": "id,total\n", "Notes.TXT": "notes", "empty/": ""})
	setMetadata(t, filepath.Join(seed, "outgoing", "orders.csv"), 0o640, stamp)
	setMetadata(t, filepath.Join(seed, "outgoing"), 0o555, stamp.Add(time.Hour))
	w := tempWorkspace(t)

	s, err := w.snapshotSeed(seed)
	if err != nil {
		t.Fatalf("SnapshotSeed: %v", err)
	}
	var m map[string]any
	b, err := os.ReadFile(filepath.Join(w.Dir(), "fixtures", "seed.json"))
	if err != nil || json.Unmarshal(b, &m) != nil {
		t.Fatalf("seed.json = %s (%v)", b, err)
	}
	if m["source"] != seed {
		t.Errorf("seed.json names the source %v, want %s", m["source"], seed)
	}
	var paths []string
	for _, e := range m["entries"].([]any) {
		paths = append(paths, e.(map[string]any)["path"].(string))
	}
	if want := []string{"Notes.TXT", "empty", "outgoing", "outgoing/orders.csv"}; !slices.Equal(paths, want) {
		t.Errorf("seed.json lists %v, want %v", paths, want)
	}
	orders := m["entries"].([]any)[3].(map[string]any)
	sum := sha256.Sum256([]byte("id,total\n"))
	if orders["type"] != "file" || orders["size"] != 9.0 || orders["mode"] != "0640" || orders["sha256"] != hex.EncodeToString(sum[:]) || orders["mtime"] != "2026-03-04T05:06:07Z" {
		t.Errorf("seed.json describes orders.csv as %v", orders)
	}
	if dir := m["entries"].([]any)[2].(map[string]any); dir["type"] != "dir" || dir["mode"] != "0555" || dir["sha256"] != nil {
		t.Errorf("seed.json describes outgoing as %v", dir)
	}

	// Later changes to the seed reach no run.
	if err := os.Chmod(filepath.Join(seed, "outgoing"), 0o755); err != nil {
		t.Fatal(err)
	}
	makeSeed(t, seed, map[string]string{"outgoing/orders.csv": "changed", "outgoing/new.csv": "new"})
	files := restore(t, w, s)
	for name, want := range map[string]string{"outgoing/orders.csv": "id,total\n", "^notes.^t^x^t": "notes"} {
		if b, err := os.ReadFile(filepath.Join(files, name)); err != nil || string(b) != want {
			t.Errorf("the run's %s holds %q (%v), want %q", name, b, err, want)
		}
	}
	if _, err := os.Stat(filepath.Join(files, "outgoing", "new.csv")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the run has a file added to the seed after the snapshot (%v)", err)
	}
	if info, err := os.Stat(filepath.Join(files, "outgoing")); err != nil || info.Mode().Perm() != 0o555 || !info.ModTime().Equal(stamp.Add(time.Hour)) {
		t.Errorf("the run's outgoing directory is %v (%v), want the snapshot's mode and time", info, err)
	}
	if info, err := os.Stat(filepath.Join(files, "empty")); err != nil || !info.IsDir() {
		t.Errorf("the run lacks the empty directory (%v)", err)
	}
}

func TestSnapshotSeedReplacesTheLastSnapshot(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	makeSeed(t, first, map[string]string{"locked/a.txt": "a"})
	setMetadata(t, filepath.Join(first, "locked"), 0o555, time.Now())
	makeSeed(t, second, map[string]string{"b.txt": "b"})
	w := tempWorkspace(t)

	if _, err := w.snapshotSeed(first); err != nil {
		t.Fatalf("SnapshotSeed: %v", err)
	}
	s, err := w.snapshotSeed(second)
	if err != nil {
		t.Fatalf("SnapshotSeed over a snapshot with a read-only directory: %v", err)
	}
	if got := listTree(t, filepath.Join(w.Dir(), "fixtures", "seed")); !slices.Equal(got, []string{"b.txt"}) {
		t.Errorf("the snapshot holds %v, want only the second seed", got)
	}
	if got := listTree(t, restore(t, w, s)); !slices.Equal(got, []string{"b.txt"}) {
		t.Errorf("the run holds %v, want only the second seed", got)
	}

	if s, err := w.snapshotSeed(""); s != nil || err != nil {
		t.Fatalf("SnapshotSeed without a seed = %v, %v, want no seed", s, err)
	}
	if got := listTree(t, filepath.Join(w.Dir(), "fixtures")); len(got) != 0 {
		t.Errorf("fixtures holds %v without a seed, want nothing", got)
	}
}

func TestRestoreRefusesASnapshotThatHasChanged(t *testing.T) {
	tests := []struct {
		name   string
		change func(t *testing.T, snapshot string)
		want   string
	}{
		{"changed content", func(t *testing.T, snapshot string) {
			writeTestFile(t, filepath.Join(snapshot, "in", "a.txt"), "A")
		}, "in/a.txt has changed in the seed snapshot"},
		{"a changed mode", func(t *testing.T, snapshot string) {
			if err := os.Chmod(filepath.Join(snapshot, "in"), 0o700); err != nil {
				t.Fatal(err)
			}
		}, "in has changed in the seed snapshot"},
		{"a removed file", func(t *testing.T, snapshot string) {
			if err := os.Remove(filepath.Join(snapshot, "in", "a.txt")); err != nil {
				t.Fatal(err)
			}
		}, "in/a.txt has gone from the seed snapshot"},
		{"an added file", func(t *testing.T, snapshot string) {
			writeTestFile(t, filepath.Join(snapshot, "in", "b.txt"), "b")
		}, "in/b.txt has been added to the seed snapshot"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seed := t.TempDir()
			makeSeed(t, seed, map[string]string{"in/a.txt": "a"})
			setMetadata(t, filepath.Join(seed, "in"), 0o755, time.Now())
			w := tempWorkspace(t)
			s, err := w.snapshotSeed(seed)
			if err != nil {
				t.Fatalf("SnapshotSeed: %v", err)
			}
			tt.change(t, filepath.Join(w.Dir(), "fixtures", "seed"))

			embedded, files := newBackend(t, w)
			if err := s.restore(embedded); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Restore = %v, want %q", err, tt.want)
			}
			if got := listTree(t, files); len(got) != 0 {
				t.Errorf("the refused restore left %v", got)
			}
		})
	}
}

func TestSnapshotSeedRefusesLinks(t *testing.T) {
	seed := t.TempDir()
	makeSeed(t, seed, map[string]string{"orders.csv": "data"})
	if err := os.Symlink("orders.csv", filepath.Join(seed, "link.csv")); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}
	_, err := tempWorkspace(t).snapshotSeed(seed)
	if !errors.Is(err, backend.ErrUnsupportedFile) || !strings.Contains(err.Error(), filepath.Join(seed, "link.csv")) {
		t.Errorf("SnapshotSeed = %v, want ErrUnsupportedFile naming the link", err)
	}
}

// makeSeed writes files, by slash-separated name, under dir. A name ending
// in a slash is a directory.
func makeSeed(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))
		if strings.HasSuffix(name, "/") {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, full, content)
	}
	// Let TempDir's cleanup empty directories made read-only.
	t.Cleanup(func() {
		filepath.WalkDir(dir, func(name string, d fs.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				os.Chmod(name, 0o755)
			}
			return nil
		})
	})
}

func setMetadata(t *testing.T, name string, mode fs.FileMode, mtime time.Time) {
	t.Helper()
	if err := os.Chtimes(name, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, mode); err != nil {
		t.Fatal(err)
	}
}

// tempWorkspace returns a temporary workspace, which the test's cleanup
// closes and deletes.
func tempWorkspace(t *testing.T) *Workspace {
	t.Helper()
	w, err := TempWorkspace()
	if err != nil {
		t.Fatalf("TempWorkspace: %v", err)
	}
	t.Cleanup(func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return w
}

// newBackend starts a run in w and returns a backend over its files, and
// the directory they are in.
func newBackend(t *testing.T, w *Workspace) (*backend.Embedded, string) {
	t.Helper()
	run, err := w.NewRun(Scenario{})
	if err != nil {
		t.Fatalf("NewRun: %v", err)
	}
	root, err := os.OpenRoot(run.Files)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	embedded, err := backend.New(root, backend.Options{Limits: backend.Limits{MaxFileBytes: 1 << 20, MaxTotalBytes: 1 << 20, MaxFiles: 100, MaxOpenFiles: 10}})
	if err != nil {
		t.Fatalf("backend.New: %v", err)
	}
	return embedded, run.Files
}

// restore restores s into a new run in w, returning the run's files.
func restore(t *testing.T, w *Workspace, s *seedSnapshot) string {
	t.Helper()
	embedded, files := newBackend(t, w)
	if err := s.restore(embedded); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	return files
}

// listTree lists the slash-separated names of everything under dir.
func listTree(t *testing.T, dir string) []string {
	t.Helper()
	var names []string
	err := filepath.WalkDir(dir, func(name string, _ fs.DirEntry, err error) error {
		if err != nil || name == dir {
			return err
		}
		rel, err := filepath.Rel(dir, name)
		names = append(names, filepath.ToSlash(rel))
		return err
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	return names
}

func writeTestFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestSnapshotSeedRefusesASeedThatOverlapsTheWorkspace checks seeds that
// hold the workspace, which a snapshot would copy into itself, and seeds
// within its fixtures, which replacing the snapshot would delete.
func TestSnapshotSeedRefusesASeedThatOverlapsTheWorkspace(t *testing.T) {
	parent := t.TempDir()
	w, err := OpenWorkspace(filepath.Join(parent, "workspace"))
	if err != nil {
		t.Fatalf("OpenWorkspace: %v", err)
	}
	t.Cleanup(func() { w.Close() })
	seed := t.TempDir()
	makeSeed(t, seed, map[string]string{"orders.csv": "id,total\n"})
	s, err := w.snapshotSeed(seed)
	if err != nil {
		t.Fatalf("snapshotSeed: %v", err)
	}

	for _, src := range []string{parent, w.Dir(), filepath.Join(w.Dir(), "fixtures"), filepath.Join(w.Dir(), "fixtures", "seed")} {
		if _, err := w.snapshotSeed(src); !errors.Is(err, ErrSeedOverlapsWorkspace) {
			t.Errorf("snapshotSeed(%s) = %v, want ErrSeedOverlapsWorkspace", src, err)
		}
	}
	if err := s.check(); err != nil {
		t.Errorf("the refused seeds changed the snapshot: %v", err)
	}
}

func TestWithinComparesDirectoriesRatherThanSpellings(t *testing.T) {
	parent := t.TempDir()
	seed := filepath.Join(parent, "seed")
	inside := filepath.Join(seed, "ws")
	if err := os.MkdirAll(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(parent, "other"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(inside, link); err != nil {
		t.Fatal(err)
	}
	t.Chdir(parent)

	type check struct {
		name, dir string
		want      bool
	}
	tests := []check{
		{inside, seed, true},
		{seed, seed, true},
		{filepath.Join("seed", "ws"), seed, true},
		{inside, "seed", true},
		{link, seed, true},
		{parent, seed, false},
		{filepath.Join(parent, "other"), seed, false},
		{"other", "seed", false},
	}
	// Only a case-insensitive volume, as macOS's is by default, has SEED.
	if upper := filepath.Join(parent, "SEED"); fileExists(upper) {
		tests = append(tests, check{inside, upper, true}, check{filepath.Join(upper, "ws"), seed, true})
	}
	for _, tt := range tests {
		if got := within(tt.name, tt.dir); got != tt.want {
			t.Errorf("within(%s, %s) = %v, want %v", tt.name, tt.dir, got, tt.want)
		}
	}
}

func fileExists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}
