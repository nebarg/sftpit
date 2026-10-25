package backend

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math"
	"os"
	"sync"
	"sync/atomic"

	"github.com/pkg/sftp"
)

// Limits bound the files a backend serves and the handles open on them.
// Each must be positive.
type Limits struct {
	// MaxFileBytes is the largest logical size a file can reach, so a file
	// written sparsely or extended by a truncate counts at its full size.
	MaxFileBytes int64

	// MaxTotalBytes bounds the logical sizes of all the files together.
	MaxTotalBytes int64

	// MaxFiles bounds the number of files and directories, not counting the
	// root.
	MaxFiles int64

	// MaxOpenFiles bounds the file handles open at once, across all
	// sessions.
	MaxOpenFiles int64
}

// ErrLimit is wrapped by the error for a change that would take the files
// past one of their Limits.
var ErrLimit = errors.New("storage limit reached")

// limitError names, by its setting, the limit a change would exceed.
type limitError struct {
	setting string
	max     int64
}

func (e *limitError) Error() string { return fmt.Sprintf("%v: %s is %d", ErrLimit, e.setting, e.max) }

func (e *limitError) Unwrap() error { return ErrLimit }

// usage keeps the files under a root, and the handles open on them, within
// their Limits. Every change to the tree is made under its lock, and the
// entries it touches are measured before and after, so the counts stay exact
// however many sessions make changes at once.
type usage struct {
	root   *os.Root
	limits Limits
	logger *slog.Logger

	mu   sync.Mutex
	used entry // the whole tree, not counting the root

	open atomic.Int64 // file handles
}

// newUsage counts what is already under root.
func newUsage(root *os.Root, limits Limits, logger *slog.Logger) (*usage, error) {
	u := &usage{root: root, limits: limits, logger: logger}
	err := fs.WalkDir(root.FS(), ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || name == "." {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		u.used = u.used.plus(entryOf(info))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("backend: count files: %w", err)
	}
	return u, nil
}

// entry is what part of the tree counts for: the logical sizes of its
// files, and its number of files and directories.
type entry struct{ bytes, files int64 }

func entryOf(info fs.FileInfo) entry {
	if info.Mode().IsRegular() {
		return entry{bytes: info.Size(), files: 1}
	}
	return entry{files: 1}
}

func (e entry) plus(o entry) entry { return entry{e.bytes + o.bytes, e.files + o.files} }

func (e entry) minus(o entry) entry { return entry{e.bytes - o.bytes, e.files - o.files} }

// change takes the lock, so that nothing else changes the tree until the
// returned function is called, and counts what the caller changes at the
// virtual paths names in the meantime.
func (u *usage) change(names ...string) (done func()) {
	u.mu.Lock()
	before := u.measure(names)
	return func() {
		u.used = u.used.plus(u.measure(names).minus(before))
		u.mu.Unlock()
	}
}

// measure adds up what the entries at the virtual paths names count for. An
// entry that cannot be found counts for nothing.
func (u *usage) measure(names []string) entry {
	var total entry
	for _, name := range names {
		if info, err := u.root.Lstat(rootName(name)); err == nil {
			total = total.plus(entryOf(info))
		}
	}
	return total
}

// lock takes the lock for a change that the caller counts itself.
func (u *usage) lock() (unlock func()) {
	u.mu.Lock()
	return u.mu.Unlock
}

// grew counts bytes that a change made under the lock added to a file.
func (u *usage) grew(bytes int64) { u.used.bytes += bytes }

// limitOnCreate returns the limit that creating an entry at the virtual path
// name would exceed, or nil if none would or the entry exists already. The
// caller holds the lock.
func (u *usage) limitOnCreate(name string) *limitError {
	if _, err := u.root.Lstat(rootName(name)); err == nil {
		return nil
	}
	if u.used.files >= u.limits.MaxFiles {
		return &limitError{"max_files", u.limits.MaxFiles}
	}
	return nil
}

// limitOnGrowth returns the limit that taking a file from size to newSize
// bytes would exceed, or nil if none would. The caller holds the lock.
func (u *usage) limitOnGrowth(size, newSize int64) *limitError {
	switch {
	case newSize <= size:
		return nil
	case newSize > u.limits.MaxFileBytes:
		return &limitError{"max_file_bytes", u.limits.MaxFileBytes}
	case u.used.bytes+newSize-size > u.limits.MaxTotalBytes:
		return &limitError{"max_total_bytes", u.limits.MaxTotalBytes}
	}
	return nil
}

// writeEnd returns the offset just past n bytes written at off, or the
// largest offset there is if that would overflow, since no limit allows it.
func writeEnd(off int64, n int) int64 {
	if off > math.MaxInt64-int64(n) {
		return math.MaxInt64
	}
	return off + int64(n)
}

// openHandle counts a new file handle as open, or returns the limit it would
// exceed. The count never passes the limit, even for a moment, so a refused
// open cannot make another one fail while a handle is free.
func (u *usage) openHandle() *limitError {
	for {
		n := u.open.Load()
		if n >= u.limits.MaxOpenFiles {
			return &limitError{"max_open_files", u.limits.MaxOpenFiles}
		}
		if u.open.CompareAndSwap(n, n+1) {
			return nil
		}
	}
}

func (u *usage) closeHandle() { u.open.Add(-1) }

// refuse logs a request on the virtual path name that would have exceeded
// limit, and returns the status the client gets for it: SSH_FX_FAILURE,
// which OpenSSH's sftp-server sends when the disk is full.
func (u *usage) refuse(name string, limit *limitError) error {
	u.logger.Warn("storage limit reached", "path", name, "limit", limit.setting, "max", limit.max)
	return errFailure
}

// blockSize is the block size statvfs reports, the usual size of a
// filesystem block.
const blockSize = 4096

// statVFS describes the files as a filesystem whose size and number of
// inodes are the limits.
func (u *usage) statVFS() *sftp.StatVFS {
	u.mu.Lock()
	defer u.mu.Unlock()
	freeBlocks := uint64(max(0, u.limits.MaxTotalBytes-u.used.bytes) / blockSize)
	freeFiles := uint64(max(0, u.limits.MaxFiles-u.used.files))
	return &sftp.StatVFS{
		Bsize:   blockSize,
		Frsize:  blockSize,
		Blocks:  uint64(u.limits.MaxTotalBytes / blockSize),
		Bfree:   freeBlocks,
		Bavail:  freeBlocks,
		Files:   uint64(u.limits.MaxFiles),
		Ffree:   freeFiles,
		Favail:  freeFiles,
		Namemax: 255,
	}
}
