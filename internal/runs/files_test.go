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

	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
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
	run := m.Status().Run.ID
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

	files, live, err := m.Files(run, "/", false)
	if err != nil || !live {
		t.Fatalf("Files = %v, live %v; want the live run's files", err, live)
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

	files, _, err = m.Files(run, "/", true)
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

	f, live, err := m.OpenFile(run, "/incoming/Orders.csv")
	if err != nil || !live {
		t.Fatalf("OpenFile = %v, live %v", err, live)
	}
	b, err := io.ReadAll(f)
	f.Close()
	if err != nil || string(b) != "id,total\n" {
		t.Errorf("read %q, %v", b, err)
	}
	if _, _, err := m.OpenFile(run, "/incoming"); !errors.Is(err, ErrNotFile) {
		t.Errorf("OpenFile of a directory = %v, want ErrNotFile", err)
	}
	if _, _, err := m.OpenFile(run, "/missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("OpenFile of a missing file = %v, want fs.ErrNotExist", err)
	}
	if _, _, err := m.Files(run, "/missing", false); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Files of a missing path = %v, want fs.ErrNotExist", err)
	}

	// A run that has ended keeps its files, which can no longer change.
	if _, err := m.Reset(t.Context(), ResetRequest{}); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if files, live, err := m.Files(run, "/new.txt", false); err != nil || live || len(files) != 1 {
		t.Errorf("Files of the ended run = %+v, live %v, %v; want its file, not live", files, live, err)
	}
	for _, id := range []string{"20261024-101500.123-3f9a", "../" + run, ""} {
		if _, _, err := m.Files(id, "/", false); !errors.Is(err, ErrUnknownRun) {
			t.Errorf("Files of run %q = %v, want ErrUnknownRun", id, err)
		}
	}
}

func TestSnapshotsListTheCopiesARunKept(t *testing.T) {
	cut := faults.Rule{ID: "cut", Match: faults.Match{Operations: []faults.Operation{faults.Write}}, Action: sftpproxy.PartialUpload{Cutoff: 5, Result: sftpproxy.Fail{Status: sftpwire.StatusFailure}}}
	m, addr := startManager(t, Options{Scenarios: map[string]config.Scenario{"cut": {Rules: []faults.Rule{cut}}}, Scenario: "cut"})
	run := m.Status().Run.ID
	if copies, err := m.Snapshots(run, false); err != nil || len(copies) != 0 {
		t.Fatalf("Snapshots before any = %+v, %v; want none", copies, err)
	}
	c, _ := dialSFTP(t, addr)
	f, err := c.Create("/Orders.csv")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("0123456789")); err == nil {
		t.Error("the upload succeeded, want it cut off")
	}
	f.Close()

	copies, err := m.Snapshots(run, true)
	if err != nil {
		t.Fatalf("Snapshots: %v", err)
	}
	want := sha256.Sum256([]byte("01234"))
	if len(copies) != 1 {
		t.Fatalf("Snapshots = %+v, want one", copies)
	}
	if s := copies[0]; s.Number != 1 || s.Path != "/Orders.csv" || s.Copy != "snapshots/1/^orders.csv" || s.Size != 5 || s.SHA256 != hex.EncodeToString(want[:]) {
		t.Errorf("snapshot = %+v, want 1 of /Orders.csv, 5 bytes, %x", s, want)
	}
	opened, s, err := m.OpenSnapshot(run, 1)
	if err != nil {
		t.Fatalf("OpenSnapshot: %v", err)
	}
	b, err := io.ReadAll(opened)
	opened.Close()
	if err != nil || string(b) != "01234" || s.Path != "/Orders.csv" {
		t.Errorf("snapshot 1 of %s holds %q, %v; want /Orders.csv holding 01234", s.Path, b, err)
	}
	if _, _, err := m.OpenSnapshot(run, 2); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("OpenSnapshot of a copy that does not exist = %v, want fs.ErrNotExist", err)
	}
	if _, err := m.Snapshots("20261024-101500.123-3f9a", false); !errors.Is(err, ErrUnknownRun) {
		t.Errorf("Snapshots of an unknown run = %v, want ErrUnknownRun", err)
	}
}
