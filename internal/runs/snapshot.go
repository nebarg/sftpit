package runs

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"strconv"
	"sync"

	"github.com/nebarg/sftpit/internal/backend"
	"github.com/nebarg/sftpit/internal/sftpproxy"
)

// maxCopyBytes bounds the copies a run keeps of the files that faulted
// handles leave behind.
const maxCopyBytes = 64 << 20

// snapshots takes the snapshots of a run's faulted files: their size and
// SHA-256 and, while the run's copies stay within their budget, a copy in
// the run's snapshots directory. No session can change a file while its
// snapshot is taken.
type snapshots struct {
	run      *Run
	embedded *backend.Embedded
	logger   *slog.Logger
	budget   int64

	mu     sync.Mutex
	copied int64
	count  int
}

func (s *snapshots) take(name string) (sftpproxy.Snapshot, error) {
	held, err := s.embedded.Hold(name)
	if err != nil {
		return sftpproxy.Snapshot{}, err
	}
	defer held.Close()
	info, err := held.Stat()
	if err != nil {
		return sftpproxy.Snapshot{}, fmt.Errorf("runs: snapshot: %w", err)
	}

	h := sha256.New()
	snap := sftpproxy.Snapshot{Copy: s.reserve(name, info.Size())}
	if snap.Copy == "" {
		snap.Size, err = io.Copy(h, held)
	} else {
		snap.Size, err = s.copy(snap.Copy, io.TeeReader(held, h))
	}
	if err != nil {
		return sftpproxy.Snapshot{}, fmt.Errorf("runs: snapshot: %w", err)
	}
	h.Sum(snap.SHA256[:0])
	return snap, nil
}

// reserve returns where to copy the file at name, of size bytes, or "" if
// the copy would take the run's copies past their budget.
func (s *snapshots) reserve(name string, size int64) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.copied+size > s.budget {
		s.logger.Info("snapshot not copied", "path", name, "size", size, "reason", fmt.Sprintf("the run's copies would exceed %d bytes", s.budget))
		return ""
	}
	s.copied += size
	s.count++
	return path.Join("snapshots", strconv.Itoa(s.count), backend.StoredName(name))
}

// copy writes the content r reads to name, relative to the run's directory,
// and deletes what it wrote if it fails.
func (s *snapshots) copy(name string, r io.Reader) (int64, error) {
	root, err := os.OpenRoot(s.run.Dir)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	if err := root.MkdirAll(path.Dir(name), 0o700); err != nil {
		return 0, err
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, r)
	if err = errors.Join(err, f.Close()); err != nil {
		root.Remove(name)
		return 0, err
	}
	return n, nil
}
