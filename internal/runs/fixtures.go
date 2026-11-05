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
	"path/filepath"
	"slices"
	"time"

	"github.com/nebarg/sftpit/internal/backend"
)

const (
	// seedDir holds the snapshot of the seed in a workspace, and
	// seedManifest describes it.
	seedDir      = "fixtures/seed"
	seedManifest = "fixtures/seed.json"

	// expectedDir holds the snapshot of the expected fixtures, and
	// expectedManifest describes it.
	expectedDir      = "fixtures/expected"
	expectedManifest = "fixtures/expected.json"
)

// fixtureSnapshot is a snapshot of a directory of fixtures: the seed that
// each run of a workspace starts from, or the expected fixtures.
type fixtureSnapshot struct {
	// what names the snapshot in errors.
	what     string
	dir      string
	manifest manifest
}

// manifest is the content of seed.json or expected.json, which records what
// a snapshot holds.
type manifest struct {
	// Source is the directory the snapshot was taken from.
	Source  string         `json:"source"`
	Entries []fixtureEntry `json:"entries"`
}

// fixtureEntry describes a directory or regular file of a snapshot.
type fixtureEntry struct {
	Path    string `json:"path"`
	Type    string `json:"type"`
	Mode    string `json:"mode"`
	ModTime string `json:"mtime"`
	Size    int64  `json:"size,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
}

// snapshotSeed replaces the workspace's seed snapshot with a copy of the
// directories and regular files under the host directory src, with their
// permission bits and modification times, and a manifest of what it holds,
// with each file's size and SHA-256. Runs restore their files from the
// snapshot, so later changes to src reach none of them. An entry that is
// neither a directory nor a regular file is an error wrapping
// backend.ErrUnsupportedFile, and a src that holds the workspace or lies
// within its fixtures is refused with ErrSeedOverlapsWorkspace, and a src
// that does not exist with an error wrapping fs.ErrNotExist, before anything
// changes. An empty src removes the snapshot and returns nil.
func (w *Workspace) snapshotSeed(src string) (*fixtureSnapshot, error) {
	return w.snapshotFixtures("seed", src, seedDir, seedManifest)
}

// snapshotExpected replaces the workspace's snapshot of the expected
// fixtures as snapshotSeed does the seed's. The snapshot lies outside every
// run's files, so no client can see it.
func (w *Workspace) snapshotExpected(src string) (*fixtureSnapshot, error) {
	return w.snapshotFixtures("expected", src, expectedDir, expectedManifest)
}

// snapshotFixtures replaces the snapshot of what in dir, with its manifest
// in manifestName, by a copy of src.
func (w *Workspace) snapshotFixtures(what, src, dir, manifestName string) (*fixtureSnapshot, error) {
	if src != "" {
		// A src that does not exist yet could come to exist below, within
		// the snapshot, unnoticed by the check of the overlap.
		if _, err := os.Stat(src); err != nil {
			return nil, fmt.Errorf("runs: snapshot the %s: %w", what, err)
		}
		if within(w.dir, src) || within(src, filepath.Join(w.dir, filepath.FromSlash(path.Dir(dir)))) {
			return nil, fmt.Errorf("runs: %s %s: %w", what, src, ErrSeedOverlapsWorkspace)
		}
	}
	if err := removeAll(w.root, dir); err != nil {
		return nil, fmt.Errorf("runs: remove the %s snapshot: %w", what, err)
	}
	if err := w.root.Remove(manifestName); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("runs: remove the %s snapshot: %w", what, err)
	}
	if src == "" {
		return nil, nil
	}
	if err := w.root.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("runs: snapshot the %s: %w", what, err)
	}
	dst, err := w.root.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("runs: snapshot the %s: %w", what, err)
	}
	defer dst.Close()
	if err := copyTree(src, dst); err != nil {
		return nil, fmt.Errorf("runs: snapshot the %s: %w", what, err)
	}
	entries, err := describeTree(dst)
	if err != nil {
		return nil, fmt.Errorf("runs: snapshot the %s: %w", what, err)
	}

	m := manifest{Source: src, Entries: entries}
	if err := writeJSON(w.root, manifestName, m); err != nil {
		return nil, fmt.Errorf("runs: record the %s snapshot: %w", what, err)
	}
	return &fixtureSnapshot{what: what, dir: filepath.Join(w.dir, filepath.FromSlash(dir)), manifest: m}, nil
}

// restore copies the snapshot into embedded, once it has checked that the
// snapshot still holds what its manifest records.
func (s *fixtureSnapshot) restore(embedded *backend.Embedded) error {
	if err := s.check(); err != nil {
		return err
	}
	if err := embedded.Seed(s.dir); err != nil {
		return fmt.Errorf("runs: restore the %s snapshot of %s: %w", s.what, s.manifest.Source, err)
	}
	return nil
}

// check reports a difference between the snapshot and its manifest: an
// entry gone or added if there is one, since that changes its directory
// too, or else the first entry that has changed.
func (s *fixtureSnapshot) check() error {
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return fmt.Errorf("runs: check the %s snapshot: %w", s.what, err)
	}
	defer root.Close()
	got, err := describeTree(root)
	if err != nil {
		return fmt.Errorf("runs: check the %s snapshot: %w", s.what, err)
	}
	want := s.manifest.Entries
	gotByPath, wantByPath := byPath(got), byPath(want)
	for _, e := range want {
		if _, ok := gotByPath[e.Path]; !ok {
			return fmt.Errorf("runs: %s has gone from the %s snapshot in %s", e.Path, s.what, s.dir)
		}
	}
	for _, e := range got {
		if _, ok := wantByPath[e.Path]; !ok {
			return fmt.Errorf("runs: %s has been added to the %s snapshot in %s", e.Path, s.what, s.dir)
		}
	}
	for _, e := range want {
		if gotByPath[e.Path] != e {
			return fmt.Errorf("runs: %s has changed in the %s snapshot in %s", e.Path, s.what, s.dir)
		}
	}
	return nil
}

func byPath(entries []fixtureEntry) map[string]fixtureEntry {
	m := make(map[string]fixtureEntry, len(entries))
	for _, e := range entries {
		m[e.Path] = e
	}
	return m
}

// copyTree copies the directories and regular files under the host
// directory src into dst, with their permission bits and modification
// times.
func copyTree(src string, dst *os.Root) error {
	srcRoot, err := os.OpenRoot(src)
	if err != nil {
		return err
	}
	defer srcRoot.Close()

	// Directories are made writable and get their own mode and time once
	// their contents are in, as backend.Embedded.Seed does.
	var dirs []string
	err = fs.WalkDir(srcRoot.FS(), ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || name == "." {
			return err
		}
		switch {
		case d.IsDir():
			dirs = append(dirs, name)
			err = dst.Mkdir(name, 0o700)
		case d.Type().IsRegular():
			err = copyFile(srcRoot, dst, name)
		default:
			err = backend.ErrUnsupportedFile
		}
		if err != nil {
			return fmt.Errorf("%s: %w", filepath.Join(src, filepath.FromSlash(name)), err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, dir := range slices.Backward(dirs) {
		if err := copyMetadata(srcRoot, dst, dir); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(srcRoot, dst *os.Root, name string) error {
	in, err := srcRoot.Open(name)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := dst.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err = errors.Join(err, out.Close()); err != nil {
		return err
	}
	return copyMetadata(srcRoot, dst, name)
}

func copyMetadata(srcRoot, dst *os.Root, name string) error {
	info, err := srcRoot.Lstat(name)
	if err != nil {
		return err
	}
	if err := dst.Chmod(name, info.Mode().Perm()); err != nil {
		return err
	}
	return dst.Chtimes(name, info.ModTime(), info.ModTime())
}

// describeTree describes every directory and regular file under root, in
// lexical order. It describes what root holds, as root's filesystem stores
// it, so that a later description of the same files is equal.
func describeTree(root *os.Root) ([]fixtureEntry, error) {
	var entries []fixtureEntry
	err := fs.WalkDir(root.FS(), ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || name == "." {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		e := fixtureEntry{Path: name, Mode: fmt.Sprintf("%04o", info.Mode().Perm()), ModTime: info.ModTime().UTC().Format(time.RFC3339Nano)}
		switch {
		case d.IsDir():
			e.Type = "dir"
		case d.Type().IsRegular():
			e.Type = "file"
			e.Size = info.Size()
			if e.SHA256, err = hashFile(root, name); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s: %w", name, backend.ErrUnsupportedFile)
		}
		entries = append(entries, e)
		return nil
	})
	return entries, err
}

func hashFile(root *os.Root, name string) (string, error) {
	f, err := root.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// within reports whether the host path name is the directory dir or lies
// under it. It compares directories rather than spellings, so a relative
// path, a symlink or a difference in letter case on a case-insensitive
// volume, as macOS's is by default, hides no overlap.
func within(name, dir string) bool {
	target, err := os.Stat(dir)
	if err != nil {
		return false
	}
	name, err = filepath.Abs(name)
	if err != nil {
		return false
	}
	name, err = filepath.EvalSymlinks(name)
	if err != nil {
		return false
	}
	for {
		if info, err := os.Stat(name); err == nil && os.SameFile(info, target) {
			return true
		}
		parent := filepath.Dir(name)
		if parent == name {
			return false
		}
		name = parent
	}
}
