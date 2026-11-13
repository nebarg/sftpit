package runs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
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
func (m *Manager) seeded() map[string]fixtureEntry {
	if m.fixtures == nil {
		return nil
	}
	files := make(map[string]fixtureEntry)
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
