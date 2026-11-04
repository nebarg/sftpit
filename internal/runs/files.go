package runs

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strconv"
	"time"

	"github.com/nebarg/sftpit/internal/backend"
)

// ErrNotFile reports a path that names a directory, or nothing a client can
// see, where a file is wanted.
var ErrNotFile = backend.ErrNotFile

// File describes a file or directory of a run, as its clients see it.
type File struct {
	backend.File

	// SHA256 is a file's hash, if it was asked for.
	SHA256 string

	// Seed is "unchanged" or "changed" for a file that the seed holds at
	// the same path, and "" otherwise. A file has changed if its size
	// differs from the seed's, or its hash if that was asked for, or else
	// its modification time.
	Seed string
}

// Files describes the file or directory name, a clean absolute path, of
// run, one of the runs the workspace keeps, and everything beneath a
// directory, sorted by path, with each file's SHA-256 if hash is set. It
// reports whether run is the current run, whose files can change while
// they are read. A run the workspace does not keep fails with
// ErrUnknownRun, and a name the run does not hold with an error wrapping
// fs.ErrNotExist.
func (m *Manager) Files(run, name string, hash bool) (files []File, live bool, err error) {
	root, err := m.workspace.openRun(run, "fs")
	if err != nil {
		return nil, false, err
	}
	defer root.Close()
	listed, err := backend.List(root, name)
	if err != nil {
		return nil, false, fmt.Errorf("runs: %w", err)
	}
	seeded := m.seeded()
	for _, f := range listed {
		file := File{File: f}
		if hash && !f.Dir {
			if file.SHA256, err = hashOf(root, f.Path); err != nil {
				return nil, false, err
			}
		}
		if e, ok := seeded[f.Path]; ok && !f.Dir {
			file.Seed = "unchanged"
			if e.Size != f.Size || (hash && e.SHA256 != file.SHA256) || (!hash && e.ModTime != f.ModTime.UTC().Format(time.RFC3339Nano)) {
				file.Seed = "changed"
			}
		}
		files = append(files, file)
	}
	return files, m.isCurrent(run), nil
}

// OpenFile opens the regular file name, a clean absolute path, of run for
// reading, and reports whether run is the current run, as Files does. A
// name that the run holds but that is not a regular file fails with
// ErrNotFile.
func (m *Manager) OpenFile(run, name string) (f *os.File, live bool, err error) {
	root, err := m.workspace.openRun(run, "fs")
	if err != nil {
		return nil, false, err
	}
	defer root.Close()
	if f, err = backend.Open(root, name); err != nil {
		return nil, false, fmt.Errorf("runs: %w", err)
	}
	return f, m.isCurrent(run), nil
}

// seeded returns the files of the seed snapshot by path, or nil if the runs
// start without a seed.
func (m *Manager) seeded() map[string]seedEntry {
	if m.fixtures == nil {
		return nil
	}
	files := make(map[string]seedEntry)
	for _, e := range m.fixtures.manifest.Entries {
		if e.Type == "file" {
			files["/"+e.Path] = e
		}
	}
	return files
}

func (m *Manager) isCurrent(run string) bool {
	return m.active().run.ID == run
}

// SnapshotCopy describes the copy that a run kept of a file that a faulted
// handle left behind.
type SnapshotCopy struct {
	// Number numbers the run's copies from 1, in the order they were taken.
	Number int

	// Path is the clean absolute path of the file the copy was taken of,
	// and Copy the copy's path in the run's directory.
	Path, Copy string

	Size    int64
	ModTime time.Time

	// SHA256 is the copy's hash, if it was asked for.
	SHA256 string
}

// Snapshots describes the copies that run, one of the runs the workspace
// keeps, kept of the files that faulted handles left behind, in the order
// they were taken, with each one's SHA-256 if hash is set. A run the
// workspace does not keep fails with ErrUnknownRun.
func (m *Manager) Snapshots(run string, hash bool) ([]SnapshotCopy, error) {
	dir, err := m.workspace.openRun(run, ".")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := fs.ReadDir(dir.FS(), snapshotsDir)
	if errors.Is(err, fs.ErrNotExist) {
		return []SnapshotCopy{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("runs: list snapshots: %w", err)
	}
	copies := []SnapshotCopy{}
	for _, e := range entries {
		n, err := strconv.Atoi(e.Name())
		if err != nil || n < 1 || strconv.Itoa(n) != e.Name() {
			continue
		}
		c, err := snapshotCopy(dir, n, hash)
		if err != nil {
			return nil, err
		}
		if c != nil {
			copies = append(copies, *c)
		}
	}
	slices.SortFunc(copies, func(a, b SnapshotCopy) int { return a.Number - b.Number })
	return copies, nil
}

// OpenSnapshot opens the copy numbered n that run kept, for reading, and
// describes it. A run the workspace does not keep fails with ErrUnknownRun,
// and a copy it does not hold with an error wrapping fs.ErrNotExist.
func (m *Manager) OpenSnapshot(run string, n int) (*os.File, SnapshotCopy, error) {
	dir, err := m.workspace.openRun(run, ".")
	if err != nil {
		return nil, SnapshotCopy{}, err
	}
	defer dir.Close()
	c, err := snapshotCopy(dir, n, false)
	if err == nil && c == nil {
		err = fmt.Errorf("runs: snapshot %d: %w", n, fs.ErrNotExist)
	}
	if err != nil {
		return nil, SnapshotCopy{}, err
	}
	f, err := dir.Open(c.Copy)
	if err != nil {
		return nil, SnapshotCopy{}, fmt.Errorf("runs: open snapshot %d: %w", n, err)
	}
	return f, *c, nil
}

// snapshotCopy describes the copy numbered n in the run directory dir, or
// returns nil if it holds none: a copy is the one file under its number's
// directory.
func snapshotCopy(dir *os.Root, n int, hash bool) (*SnapshotCopy, error) {
	sub := path.Join(snapshotsDir, strconv.Itoa(n))
	root, err := dir.OpenRoot(sub)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("runs: snapshot %d: %w", n, err)
	}
	defer root.Close()
	files, err := backend.List(root, "/")
	if err != nil {
		return nil, fmt.Errorf("runs: snapshot %d: %w", n, err)
	}
	for _, f := range files {
		if f.Dir {
			continue
		}
		c := &SnapshotCopy{Number: n, Path: f.Path, Copy: path.Join(sub, backend.StoredName(f.Path)), Size: f.Size, ModTime: f.ModTime}
		if hash {
			if c.SHA256, err = hashOf(root, f.Path); err != nil {
				return nil, err
			}
		}
		return c, nil
	}
	return nil, nil
}

// hashOf returns the SHA-256 of the file name, a clean absolute path, among
// the files that root stores as the backend stores them.
func hashOf(root *os.Root, name string) (string, error) {
	f, err := backend.Open(root, name)
	if err != nil {
		return "", fmt.Errorf("runs: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("runs: hash %s: %w", name, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// OpenTrace opens the trace of run, one of the runs the workspace keeps,
// for reading, and returns the size of the whole lines in it. The trace of
// a run whose events the Manager keeps, the current run's among them, may
// end in part of a line still being written, which size leaves out. A run
// the workspace does not keep fails with ErrUnknownRun, and one without a
// trace, from an older sftpit, with an error wrapping fs.ErrNotExist.
func (m *Manager) OpenTrace(run string) (f *os.File, size int64, err error) {
	dir, err := m.workspace.openRun(run, ".")
	if err != nil {
		return nil, 0, err
	}
	defer dir.Close()
	if f, err = dir.Open(traceFile); err != nil {
		return nil, 0, fmt.Errorf("runs: open the trace: %w", err)
	}
	if rec, err := m.Events(run); err == nil {
		return f, rec.Trace().Size, nil
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, fmt.Errorf("runs: open the trace: %w", err)
	}
	return f, info.Size(), nil
}
