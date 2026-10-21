package backend

import (
	"errors"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/pkg/sftp"
)

// handler implements pkg/sftp's request handlers on top of a root. pkg/sftp
// passes it absolute virtual paths that it has already cleaned.
type handler struct {
	root  *os.Root
	holds *holds
	usage *usage
}

// pkg/sftp finds the optional interfaces by type assertion and falls back
// silently, so a signature that drifts on upgrade would change behavior
// without failing the build.
var (
	_ sftp.FileReader           = (*handler)(nil)
	_ sftp.OpenFileWriter       = (*handler)(nil)
	_ sftp.PosixRenameFileCmder = (*handler)(nil)
	_ sftp.StatVFSFileCmder     = (*handler)(nil)
	_ sftp.LstatFileLister      = (*handler)(nil)
)

func (h *handler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	f, err := h.open(r.Filepath, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	return &file{f: f, usage: h.usage}, nil
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
	// An open that cannot write neither waits for a snapshot nor holds back
	// other changes, unless it creates or truncates the file.
	if pflags.Write || flag&(os.O_CREATE|os.O_TRUNC) != 0 {
		defer h.changing(r.Filepath)()
		if flag&os.O_CREATE != 0 {
			if limit := h.usage.limitOnCreate(r.Filepath); limit != nil {
				return nil, h.usage.refuse(r.Filepath, limit)
			}
		}
	}
	f, err := h.open(r.Filepath, flag)
	if err != nil {
		return nil, err
	}
	if !pflags.Write {
		return &file{f: f, usage: h.usage}, nil
	}
	return &file{f: f, usage: h.usage, appending: pflags.Append, name: r.Filepath, holds: h.holds}, nil
}

// open opens the file at the virtual path name with flag, as long as another
// file handle can be open.
func (h *handler) open(name string, flag int) (*os.File, error) {
	if limit := h.usage.openHandle(); limit != nil {
		return nil, h.usage.refuse(name, limit)
	}
	// pkg/sftp passes the open flags where an OPEN's attribute flags belong,
	// so the permissions a client sends cannot be told apart from noise.
	f, err := h.root.OpenFile(rootName(name), flag, 0o666)
	if err != nil {
		h.usage.closeHandle()
		return nil, statusError(err)
	}
	return f, nil
}

// changing waits until no snapshot holds any of the virtual paths names,
// and then keeps every other change to the tree waiting until the returned
// function is called, counting what the caller changes at names. Empty names
// are ignored.
func (h *handler) changing(names ...string) (done func()) {
	released := h.holds.change(names...)
	counted := h.usage.change(names...)
	return func() {
		counted()
		released()
	}
}

func (h *handler) Filecmd(r *sftp.Request) error {
	defer h.changing(r.Filepath, r.Target)()
	name := rootName(r.Filepath)
	switch r.Method {
	case "Setstat":
		return h.setstat(name, r)
	case "Rename":
		return h.rename(name, rootName(r.Target))
	case "Mkdir":
		if limit := h.usage.limitOnCreate(r.Filepath); limit != nil {
			return h.usage.refuse(r.Filepath, limit)
		}
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
	defer h.changing(r.Filepath, r.Target)()
	return statusError(h.root.Rename(rootName(r.Filepath), rootName(r.Target)))
}

// StatVFS describes the limits as the filesystem holding every path.
func (h *handler) StatVFS(r *sftp.Request) (*sftp.StatVFS, error) {
	if _, err := h.root.Stat(rootName(r.Filepath)); err != nil {
		return nil, statusError(err)
	}
	return h.usage.statVFS(), nil
}

// setstat applies each attribute in turn and, like OpenSSH, attempts every
// one even after a failure, reporting the last failure.
func (h *handler) setstat(name string, r *sftp.Request) error {
	flags := r.AttrFlags()
	attrs := r.Attributes()
	var err error
	if flags.Size {
		if truncErr := h.truncate(r.Filepath, int64(attrs.Size)); truncErr != nil {
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

// truncate sets the size of the file at the virtual path name, unless that
// would take the files past a limit.
func (h *handler) truncate(name string, size int64) error {
	f, err := h.root.OpenFile(rootName(name), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if limit := h.usage.limitOnGrowth(info.Size(), size); limit != nil {
		return h.usage.refuse(name, limit)
	}
	if err := f.Truncate(size); err != nil {
		return err
	}
	return f.Close()
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

// list lists the directory name under the virtual names of its entries,
// leaving out any entry whose name sftpit cannot have given it, such as a
// file copied into the root by hand.
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
	var list listerAt
	for _, e := range entries {
		if virtual, ok := decodeName(e.Name()); ok {
			list = append(list, namedInfo{FileInfo: e, name: virtual})
		}
	}
	return list, nil
}

// namedInfo is a FileInfo under another name.
type namedInfo struct {
	os.FileInfo
	name string
}

func (i namedInfo) Name() string { return i.name }

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
	f     *os.File
	usage *usage

	// appending, name and holds are set for a handle that can write, whose
	// writes wait for any snapshot of its file.
	appending bool
	name      string
	holds     *holds
}

func (f *file) ReadAt(p []byte, off int64) (int, error) {
	n, err := f.f.ReadAt(p, off)
	return n, statusError(err)
}

func (f *file) WriteAt(p []byte, off int64) (int, error) {
	if f.holds == nil {
		// The descriptor is read-only, so the write fails.
		n, err := f.f.WriteAt(p, off)
		return n, statusError(err)
	}
	defer f.holds.change(f.name)()
	// Under the lock the size cannot change between the check and the write,
	// so appends through several handles land one after another.
	defer f.usage.lock()()
	info, err := f.f.Stat()
	if err != nil {
		return 0, statusError(err)
	}
	size := info.Size()
	if f.appending {
		off = size
	}
	if limit := f.usage.limitOnGrowth(size, writeEnd(off, len(p))); limit != nil {
		return 0, f.usage.refuse(f.name, limit)
	}
	n, err := f.f.WriteAt(p, off)
	f.usage.grew(max(0, off+int64(n)-size))
	return n, statusError(err)
}

func (f *file) Close() error {
	err := f.f.Close()
	f.usage.closeHandle()
	return statusError(err)
}
