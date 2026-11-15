package backend

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"time"
)

// ErrNotFile reports a path that names a directory, or nothing a client can
// see, where a file is wanted.
var ErrNotFile = errors.New("not a file")

// File describes a file or directory as a backend's clients see it.
type File struct {
	// Path is the file's clean absolute path.
	Path    string
	Dir     bool
	Size    int64
	Mode    fs.FileMode
	ModTime time.Time
}

// List describes the file or directory at name, a clean absolute path,
// among the files that root stores as a backend stores them, and, for a
// directory, everything beneath it, sorted by path. It leaves out anything
// but directories and regular files, such as a symlink put there by hand,
// and does not descend into one. A name that root does not hold fails with
// an error wrapping fs.ErrNotExist.
func List(root *os.Root, name string) ([]File, error) {
	var files []File
	err := fs.WalkDir(root.FS(), rootName(name), func(stored string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		f := File{Path: path.Join("/", stored), Dir: d.IsDir(), Mode: info.Mode().Perm(), ModTime: info.ModTime()}
		if !f.Dir {
			f.Size = info.Size()
		}
		files = append(files, f)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("backend: list %s: %w", name, err)
	}
	return files, nil
}

// Open opens the regular file at name, a clean absolute path, among the
// files that root stores as a backend stores them, for reading. A name that
// root does not hold fails with an error wrapping fs.ErrNotExist, and one
// that is not a regular file with ErrNotFile.
func Open(root *os.Root, name string) (*os.File, error) {
	f, err := root.Open(rootName(name))
	if err != nil {
		return nil, fmt.Errorf("backend: open %s: %w", name, err)
	}
	info, err := f.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = ErrNotFile
	}
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("backend: open %s: %w", name, err)
	}
	return f, nil
}
