package runs

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestFilesDescribeARunsFilesAgainstTheSeed(t *testing.T) {
	seed := t.TempDir()
	if err := os.Mkdir(filepath.Join(seed, "incoming"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"incoming/Orders.csv": "id\n", "kept.txt": "same", "rewritten.txt": "same"} {
		if err := os.WriteFile(filepath.Join(seed, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	m, addr := startManager(t, Options{SeedDir: seed})
	c, _ := dialSFTP(t, addr)
	for name, content := range map[string]string{"/incoming/Orders.csv": "id,total\n", "/new.txt": "new", "/rewritten.txt": "same"} {
		f, err := c.Create(name)
		if err != nil {
			t.Fatalf("Create %s: %v", name, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("Write %s: %v", name, err)
		}
		f.Close()
	}

	files, err := m.Files("/", false)
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	got := map[string]string{}
	var paths []string
	for _, f := range files {
		paths = append(paths, f.Path)
		got[f.Path] = f.Seed
	}
	if want := []string{"/", "/incoming", "/incoming/Orders.csv", "/kept.txt", "/new.txt", "/rewritten.txt"}; !slices.Equal(paths, want) {
		t.Errorf("paths = %q, want %q", paths, want)
	}
	// Without hashes, a file rewritten with the same content has changed,
	// since its modification time has.
	want := map[string]string{"/": "", "/incoming": "", "/incoming/Orders.csv": "changed", "/kept.txt": "unchanged", "/new.txt": "", "/rewritten.txt": "changed"}
	if !maps.Equal(got, want) {
		t.Errorf("seed = %v, want %v", got, want)
	}

	files, err = m.Files("/", true)
	if err != nil {
		t.Fatalf("Files with hashes: %v", err)
	}
	for _, f := range files {
		switch f.Path {
		case "/new.txt":
			if want := sha256.Sum256([]byte("new")); f.SHA256 != hex.EncodeToString(want[:]) {
				t.Errorf("%s: SHA-256 %s, want %x", f.Path, f.SHA256, want)
			}
		case "/rewritten.txt":
			if f.Seed != "unchanged" {
				t.Errorf("%s with hashes: %q, want unchanged, as its content is", f.Path, f.Seed)
			}
		case "/incoming":
			if f.SHA256 != "" {
				t.Errorf("a directory has SHA-256 %s", f.SHA256)
			}
		}
	}

	f, err := m.OpenFile("/incoming/Orders.csv")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	b, err := io.ReadAll(f)
	f.Close()
	if err != nil || string(b) != "id,total\n" {
		t.Errorf("read %q, %v", b, err)
	}
	if _, err := m.OpenFile("/incoming"); !errors.Is(err, ErrNotFile) {
		t.Errorf("OpenFile of a directory = %v, want ErrNotFile", err)
	}
	if _, err := m.OpenFile("/missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("OpenFile of a missing file = %v, want fs.ErrNotExist", err)
	}
	if _, err := m.Files("/missing", false); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Files of a missing path = %v, want fs.ErrNotExist", err)
	}
}
