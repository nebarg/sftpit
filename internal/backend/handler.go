package backend

import (
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/sftp"
)

// handler implements pkg/sftp's request handlers on top of a root. pkg/sftp
// passes it absolute virtual paths that it has already cleaned.
type handler struct {
	root *os.Root
}

// rootName converts a clean absolute virtual path into a name relative to
// the root.
func rootName(virtual string) string {
	if virtual == "/" {
		return "."
	}
	return strings.TrimPrefix(virtual, "/")
}

func (h *handler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	f, err := h.root.Open(rootName(r.Filepath))
	if err != nil {
		return nil, statusError(err)
	}
	return &file{f: f}, nil
}

func (h *handler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	return h.openFile(r)
}

func (h *handler) OpenFile(r *sftp.Request) (sftp.WriterAtReaderAt, error) {
	return h.openFile(r)
}

func (h *handler) openFile(r *sftp.Request) (*file, error) {
	pflags := r.Pflags()
	var flag int
	switch {
	case pflags.Read && pflags.Write:
		flag = os.O_RDWR
	case pflags.Write:
		flag = os.O_WRONLY
	default:
		flag = os.O_RDONLY
	}
	if pflags.Creat {
		flag |= os.O_CREATE
	}
	if pflags.Trunc {
		flag |= os.O_TRUNC
	}
	if pflags.Excl {
		flag |= os.O_EXCL
	}
	// pkg/sftp passes the open flags where an OPEN's attribute flags belong,
	// so the permissions a client sends cannot be told apart from noise.
	f, err := h.root.OpenFile(rootName(r.Filepath), flag, 0o666)
	if err != nil {
		return nil, statusError(err)
	}
	return &file{f: f, appending: pflags.Append}, nil
}

func (h *handler) Filecmd(r *sftp.Request) error {
	name := rootName(r.Filepath)
	switch r.Method {
	case "Setstat":
		return h.setstat(name, r)
	case "Rename":
		return h.rename(name, rootName(r.Target))
	case "Mkdir":
		// pkg/sftp drops the attributes a MKDIR carries.
		return statusError(h.root.Mkdir(name, 0o777))
	case "Rmdir":
		return h.rmdir(name)
	case "Remove":
		return h.remove(name)
	}
	return errOpUnsupported
}

func (h *handler) PosixRename(r *sftp.Request) error {
	return statusError(h.root.Rename(rootName(r.Filepath), rootName(r.Target)))
}

// setstat applies each attribute in turn and, like OpenSSH, attempts every
// one even after a failure, reporting the last failure.
func (h *handler) setstat(name string, r *sftp.Request) error {
	flags := r.AttrFlags()
	attrs := r.Attributes()
	var err error
	if flags.Size {
		if truncErr := h.truncate(name, int64(attrs.Size)); truncErr != nil {
			err = truncErr
		}
	}
	if flags.Permissions {
		if chmodErr := h.root.Chmod(name, permissions(attrs.Mode)); chmodErr != nil {
			err = chmodErr
		}
	}
	if flags.Acmodtime {
		atime := time.Unix(int64(attrs.Atime), 0)
		mtime := time.Unix(int64(attrs.Mtime), 0)
		if chtimesErr := h.root.Chtimes(name, atime, mtime); chtimesErr != nil {
			err = chtimesErr
		}
	}
	if flags.UidGid {
		err = errPermissionDenied
	}
	return statusError(err)
}

func (h *handler) truncate(name string, size int64) error {
	f, err := h.root.OpenFile(name, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	err = f.Truncate(size)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}

// rename implements the standard rename, which fails when the target exists.
// Like OpenSSH, it renames a regular file by linking and then unlinking it,
// so a concurrently created target is never replaced, and falls back to a
// check followed by a rename where links are not supported.
func (h *handler) rename(from, to string) error {
	info, err := h.root.Lstat(from)
	if err != nil {
		return statusError(err)
	}
	if info.Mode().IsRegular() {
		err := h.root.Link(from, to)
		if err == nil {
			if err := h.root.Remove(from); err != nil {
				h.root.Remove(to)
				return statusError(err)
			}
			return nil
		}
		if !errors.Is(err, errors.ErrUnsupported) && !errors.Is(err, syscall.EXDEV) {
			return statusError(err)
		}
	}
	if _, err := h.root.Stat(to); err == nil {
		return errFailure
	}
	return statusError(h.root.Rename(from, to))
}

// rmdir removes only a directory, as rmdir(2) does. os.Root.Remove would
// also remove a file.
func (h *handler) rmdir(name string) error {
	info, err := h.root.Lstat(name)
	if err != nil {
		return statusError(err)
	}
	if !info.IsDir() {
		return statusError(syscall.ENOTDIR)
	}
	return statusError(h.root.Remove(name))
}

// remove removes only a non-directory, as unlink(2) does on Linux.
// os.Root.Remove would also remove an empty directory.
func (h *handler) remove(name string) error {
	info, err := h.root.Lstat(name)
	if err != nil {
		return statusError(err)
	}
	if info.IsDir() {
		return statusError(syscall.EISDIR)
	}
	return statusError(h.root.Remove(name))
}

func (h *handler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	name := rootName(r.Filepath)
	switch r.Method {
	case "List":
		return h.list(name)
	case "Stat":
		info, err := h.root.Stat(name)
		if err != nil {
			return nil, statusError(err)
		}
		return listerAt{info}, nil
	}
	return nil, errOpUnsupported
}

func (h *handler) Lstat(r *sftp.Request) (sftp.ListerAt, error) {
	info, err := h.root.Lstat(rootName(r.Filepath))
	if err != nil {
		return nil, statusError(err)
	}
	return listerAt{info}, nil
}

func (h *handler) list(name string) (sftp.ListerAt, error) {
	dir, err := h.root.Open(name)
	if err != nil {
		return nil, statusError(err)
	}
	defer dir.Close()
	entries, err := dir.Readdir(-1)
	if err != nil {
		return nil, statusError(err)
	}
	return listerAt(entries), nil
}

// permissions converts SFTP permission bits into a file mode. The setuid,
// setgid and sticky bits are dropped, so a client cannot leave a setuid
// program in the developer's workspace.
func permissions(mode uint32) os.FileMode {
	return os.FileMode(mode) & os.ModePerm
}

type listerAt []os.FileInfo

func (l listerAt) ListAt(dst []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(dst, l[offset:])
	if n < len(dst) {
		return n, io.EOF
	}
	return n, nil
}

// file is an open file handle. Writes on a handle opened for appending go to
// the end of the file whatever offset the client sends, as with OpenSSH's
// O_APPEND handles; they are positional writes at the current size rather
// than writes on an O_APPEND descriptor, which os.File.WriteAt refuses.
type file struct {
	f         *os.File
	appending bool
	appendMu  sync.Mutex
}

func (f *file) ReadAt(p []byte, off int64) (int, error) {
	n, err := f.f.ReadAt(p, off)
	return n, statusError(err)
}

func (f *file) WriteAt(p []byte, off int64) (int, error) {
	if f.appending {
		f.appendMu.Lock()
		defer f.appendMu.Unlock()
		info, err := f.f.Stat()
		if err != nil {
			return 0, statusError(err)
		}
		off = info.Size()
	}
	n, err := f.f.WriteAt(p, off)
	return n, statusError(err)
}

func (f *file) Close() error {
	return statusError(f.f.Close())
}
