package runs

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"golang.org/x/sys/unix"

	"github.com/nebarg/sftpit/internal/faults"
)

var (
	// ErrNotWorkspace reports a directory that holds files but no workspace
	// marker, or a marker sftpit cannot use.
	ErrNotWorkspace = errors.New("not an sftpit workspace")

	// ErrInUse reports a workspace that another process has locked.
	ErrInUse = errors.New("workspace in use by another sftpit process")

	// ErrSeedOverlapsWorkspace reports a seed directory that holds the
	// workspace or lies within its fixtures, so that snapshotting it would
	// copy it into itself or delete it.
	ErrSeedOverlapsWorkspace = errors.New("the seed directory overlaps the workspace, so it would be copied into itself or deleted")

	// errLocked reports a lock that another process holds.
	errLocked = errors.New("runs: file locked")
)

const (
	markerName  = "workspace.json"
	lockName    = "workspace.lock"
	identityDir = "identity"
	runsDir     = "runs"

	// workspaceVersion is the layout version the marker records.
	workspaceVersion = 1

	// keptRuns is how many runs a workspace keeps, the newest among them.
	keptRuns = 5
)

// marker is the content of workspace.json, which claims a directory for
// sftpit.
type marker struct {
	Owner   string `json:"owner"`
	Version int    `json:"version"`
}

// Workspace is a directory that sftpit owns, holding the host keys and the
// files of each run. A process locks the workspace while it uses it, so two
// cannot use the same one.
type Workspace struct {
	dir       string
	root      *os.Root
	lock      *os.File
	temporary bool
}

// OpenWorkspace opens the workspace in dir and locks it. A missing or empty
// directory becomes a new workspace. Any other directory without a
// workspace marker is refused with ErrNotWorkspace, and a workspace another
// process has locked with ErrInUse.
func OpenWorkspace(dir string) (*Workspace, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("runs: create workspace: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("runs: open workspace: %w", err)
	}
	w := &Workspace{dir: dir, root: root}
	if err := w.claim(); err != nil {
		if w.lock != nil {
			w.lock.Close()
		}
		root.Close()
		return nil, err
	}
	return w, nil
}

// TempWorkspace makes a workspace in a new temporary directory, which Close
// deletes.
func TempWorkspace() (*Workspace, error) {
	dir, err := os.MkdirTemp("", "sftpit-")
	if err != nil {
		return nil, fmt.Errorf("runs: create workspace: %w", err)
	}
	w, err := OpenWorkspace(dir)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	w.temporary = true
	return w, nil
}

// claim checks that the directory is empty or already a workspace, locks
// it, and marks it as a workspace if it is new.
func (w *Workspace) claim() error {
	entries, err := fs.ReadDir(w.root.FS(), ".")
	if err != nil {
		return fmt.Errorf("runs: open workspace: %w", err)
	}
	marked := slices.ContainsFunc(entries, func(e fs.DirEntry) bool { return e.Name() == markerName })
	if marked {
		if err := w.checkMarker(); err != nil {
			return err
		}
	} else if slices.ContainsFunc(entries, func(e fs.DirEntry) bool { return e.Name() != lockName }) {
		// A lock file alone is what a start interrupted before marking the
		// directory leaves behind.
		return fmt.Errorf("runs: %s is not empty: %w", w.dir, ErrNotWorkspace)
	}

	lock, err := w.root.OpenFile(lockName, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("runs: lock workspace: %w", err)
	}
	if err := lockFile(lock); err != nil {
		lock.Close()
		if errors.Is(err, errLocked) {
			return fmt.Errorf("runs: %s: %w", w.dir, ErrInUse)
		}
		return fmt.Errorf("runs: lock workspace: %w", err)
	}
	w.lock = lock
	if marked {
		return nil
	}
	// Another process may have made the directory a workspace between the
	// listing and the lock.
	if _, err := w.root.Stat(markerName); err == nil {
		return w.checkMarker()
	}
	if err := writeJSON(w.root, markerName, marker{Owner: "sftpit", Version: workspaceVersion}); err != nil {
		return fmt.Errorf("runs: mark workspace: %w", err)
	}
	return nil
}

// writeJSON writes v, indented, to the file name under root.
func writeJSON(root *os.Root, name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return root.WriteFile(name, append(b, '\n'), 0o600)
}

func (w *Workspace) checkMarker() error {
	b, err := w.root.ReadFile(markerName)
	if err != nil {
		return fmt.Errorf("runs: open workspace: %w", err)
	}
	var m marker
	if err := json.Unmarshal(b, &m); err != nil || m.Owner != "sftpit" {
		return fmt.Errorf("runs: %s has a %s that sftpit did not write: %w", w.dir, markerName, ErrNotWorkspace)
	}
	if m.Version > workspaceVersion {
		return fmt.Errorf("runs: %s was made by a newer sftpit, with layout version %d: %w", w.dir, m.Version, ErrNotWorkspace)
	}
	return nil
}

// Dir returns the workspace's directory.
func (w *Workspace) Dir() string { return w.dir }

// Temporary reports whether Close deletes the workspace.
func (w *Workspace) Temporary() bool { return w.temporary }

// IdentityDir returns the directory for the workspace's own host keys.
func (w *Workspace) IdentityDir() string { return filepath.Join(w.dir, identityDir) }

// Close unlocks the workspace and, if it is temporary, deletes it.
func (w *Workspace) Close() error {
	var err error
	if w.temporary {
		err = makeRemovable(w.root, ".")
	}
	err = errors.Join(err, w.lock.Close(), w.root.Close())
	if w.temporary {
		err = errors.Join(err, os.RemoveAll(w.dir))
	}
	if err != nil {
		return fmt.Errorf("runs: close workspace: %w", err)
	}
	return nil
}

// Run is one run in a workspace.
type Run struct {
	// ID identifies the run, among the runs of every workspace.
	ID string

	// Dir is the run's directory, and Files the directory its SFTP clients
	// see.
	Dir, Files string

	Scenario Scenario
}

// Scenario is the scenario whose faults a run starts with.
type Scenario struct {
	// Name names the scenario, or is "" for a run that starts without
	// faults or with an inline scenario.
	Name string

	// Inline reports whether the scenario was given at the reset that
	// started the run, rather than named in the configuration.
	Inline bool

	// Seed fixes the run's random decisions, those of rules applied during
	// the run included, and Pinned reports whether it was given rather than
	// drawn for the run.
	Seed   faults.Seed
	Pinned bool
}

// runRecord is the content of a run's run.json.
type runRecord struct {
	ID         string      `json:"id"`
	Started    time.Time   `json:"started"`
	Scenario   string      `json:"scenario,omitempty"`
	Inline     bool        `json:"inline,omitempty"`
	Seed       faults.Seed `json:"seed"`
	SeedPinned bool        `json:"seed_pinned,omitempty"`
}

// runIDPattern matches the IDs NewRun gives. They sort in the order the
// runs started.
var runIDPattern = regexp.MustCompile(`^\d{8}-\d{6}\.\d{3}-[0-9a-f]{4}$`)

// NewRun starts a run of scenario with no files, and deletes the oldest runs
// so that the workspace keeps the newest five.
func (w *Workspace) NewRun(scenario Scenario) (*Run, error) {
	started := time.Now().UTC()
	suffix := make([]byte, 2)
	rand.Read(suffix)
	id := started.Format("20060102-150405.000") + "-" + hex.EncodeToString(suffix)

	// Names under the root are slash-separated on every OS.
	rel := path.Join(runsDir, id)
	if err := w.root.MkdirAll(path.Join(rel, "fs"), 0o700); err != nil {
		return nil, fmt.Errorf("runs: create run: %w", err)
	}
	record := runRecord{ID: id, Started: started, Scenario: scenario.Name, Inline: scenario.Inline, Seed: scenario.Seed, SeedPinned: scenario.Pinned}
	if err := writeJSON(w.root, path.Join(rel, "run.json"), record); err != nil {
		return nil, fmt.Errorf("runs: create run: %w", err)
	}
	if err := w.prune(id); err != nil {
		return nil, err
	}
	dir := filepath.Join(w.dir, filepath.FromSlash(rel))
	return &Run{ID: id, Dir: dir, Files: filepath.Join(dir, "fs"), Scenario: scenario}, nil
}

// prune deletes the oldest runs beyond the newest keptRuns, never current.
// It leaves alone anything in runs/ that NewRun did not name.
func (w *Workspace) prune(current string) error {
	entries, err := fs.ReadDir(w.root.FS(), runsDir)
	if err != nil {
		return fmt.Errorf("runs: list runs: %w", err)
	}
	var ids []string
	for _, e := range entries {
		if e.IsDir() && runIDPattern.MatchString(e.Name()) && e.Name() != current {
			ids = append(ids, e.Name())
		}
	}
	slices.Sort(ids)
	for _, id := range ids[:max(0, len(ids)-(keptRuns-1))] {
		if err := removeAll(w.root, path.Join(runsDir, id)); err != nil {
			return fmt.Errorf("runs: delete old run: %w", err)
		}
	}
	return nil
}

// removeAll removes name, relative to root, and everything under it.
func removeAll(root *os.Root, name string) error {
	if err := makeRemovable(root, name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return root.RemoveAll(name)
}

// makeRemovable gives the owner full access to name, relative to root, and
// to every directory under it. A client can leave a directory that cannot
// be listed or written, whose entries could not otherwise be removed.
func makeRemovable(root *os.Root, name string) error {
	return fs.WalkDir(root.FS(), name, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			err = root.Chmod(p, 0o700)
		}
		return err
	})
}

// lockFile takes an exclusive lock on f, which lasts until f is closed or
// the process ends, or returns errLocked if another holds one.
func lockFile(f *os.File) error {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) {
		return errLocked
	}
	return err
}
