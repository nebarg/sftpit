package backend_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/backend"
)

func TestSeedCopiesFilesAndDirectories(t *testing.T) {
	seed := t.TempDir()
	stamp := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	writeHostFile(t, filepath.Join(seed, "outgoing", "orders.csv"), "id,total\n1,9.99\n")
	writeHostFile(t, filepath.Join(seed, "outgoing", "2026", "archive.csv"), "old")
	writeHostFile(t, filepath.Join(seed, "README"), "top level")
	if err := os.Mkdir(filepath.Join(seed, "incoming"), 0o755); err != nil {
		t.Fatal(err)
	}
	setMetadata(t, filepath.Join(seed, "outgoing", "orders.csv"), 0o640, stamp)
	setMetadata(t, filepath.Join(seed, "outgoing", "2026"), 0o750, stamp)
	setMetadata(t, filepath.Join(seed, "outgoing"), 0o555, stamp)

	dir, e := newBackend(t)
	t.Cleanup(func() {
		// Let TempDir's cleanup empty the read-only directories.
		os.Chmod(filepath.Join(seed, "outgoing"), 0o755)
		os.Chmod(filepath.Join(dir, "outgoing"), 0o755)
	})
	if err := e.Seed(seed); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	assertFile(t, filepath.Join(dir, "outgoing", "orders.csv"), "id,total\n1,9.99\n")
	assertFile(t, filepath.Join(dir, "outgoing", "2026", "archive.csv"), "old")
	// Seeded names are encoded on the host like any others.
	assertFile(t, filepath.Join(dir, "^r^e^a^d^m^e"), "top level")
	if info, err := os.Stat(filepath.Join(dir, "incoming")); err != nil || !info.IsDir() {
		t.Errorf("empty directory not copied: %v", err)
	}
	for name, mode := range map[string]os.FileMode{
		"outgoing/orders.csv": 0o640,
		"outgoing/2026":       0o750 | os.ModeDir,
		"outgoing":            0o555 | os.ModeDir,
	} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode() != mode {
			t.Errorf("%s: mode %v, want %v", name, info.Mode(), mode)
		}
		if !info.ModTime().Equal(stamp) {
			t.Errorf("%s: mtime %v, want %v", name, info.ModTime(), stamp)
		}
	}

	c := newClient(t, e, "/")
	for _, name := range []string{"/outgoing/orders.csv", "/README"} {
		f, err := c.Open(name)
		if err != nil {
			t.Fatalf("Open the seeded %s: %v", name, err)
		}
		f.Close()
	}
}

func TestSeedIsACopy(t *testing.T) {
	seed := t.TempDir()
	writeHostFile(t, filepath.Join(seed, "orders.csv"), "original")
	dir, e := newBackend(t)
	if err := e.Seed(seed); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	c := newClient(t, e, "/")
	if err := c.Remove("/orders.csv"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	assertFile(t, filepath.Join(seed, "orders.csv"), "original")
	writeHostFile(t, filepath.Join(seed, "later.csv"), "added after seeding")
	assertMissing(t, filepath.Join(dir, "later.csv"))
}

func TestSeedRejectsSymlinks(t *testing.T) {
	seed := t.TempDir()
	writeHostFile(t, filepath.Join(seed, "orders.csv"), "data")
	if err := os.Symlink("orders.csv", filepath.Join(seed, "link.csv")); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}
	_, e := newBackend(t)

	err := e.Seed(seed)
	if !errors.Is(err, backend.ErrUnsupportedFile) || !strings.Contains(err.Error(), "link.csv") {
		t.Errorf("Seed error = %v, want ErrUnsupportedFile naming link.csv", err)
	}
}

func TestSeedReportsAMissingDirectory(t *testing.T) {
	_, e := newBackend(t)
	if err := e.Seed(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Seed error = %v, want ErrNotExist", err)
	}
}

func setMetadata(t *testing.T, name string, mode os.FileMode, mtime time.Time) {
	t.Helper()
	if err := os.Chmod(name, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(name, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}
