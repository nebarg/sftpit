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
// the current run, and everything beneath a directory, sorted by path, with
// each file's SHA-256 if hash is set. A name the run does not hold fails
// with an error wrapping fs.ErrNotExist.
func (m *Manager) Files(name string, hash bool) ([]File, error) {
	root, err := m.openFiles()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	listed, err := backend.List(root, name)
	if err != nil {
		return nil, fmt.Errorf("runs: %w", err)
	}
	var files []File
	seeded := m.seeded()
	for _, f := range listed {
		file := File{File: f}
		if hash && !f.Dir {
			if file.SHA256, err = hashOf(root, f.Path); err != nil {
				return nil, err
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
	return files, nil
}

// OpenFile opens the regular file name, a clean absolute path, of the
// current run for reading. A name that the run holds but that is not a
// regular file fails with ErrNotFile.
func (m *Manager) OpenFile(name string) (*os.File, error) {
	root, err := m.openFiles()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := backend.Open(root, name)
	if err != nil {
		return nil, fmt.Errorf("runs: %w", err)
	}
	return f, nil
}

// openFiles opens the directory of the current run's files. It opens its
// own root, rather than sharing the run's, which a reset closes.
func (m *Manager) openFiles() (*os.Root, error) {
	root, err := os.OpenRoot(m.active().run.Files)
	if err != nil {
		return nil, fmt.Errorf("runs: open run files: %w", err)
	}
	return root, nil
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
