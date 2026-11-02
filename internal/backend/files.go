package backend

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"
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
// directory, everything beneath it, sorted by path. Like the backend, it
// leaves out names that the backend cannot have given and anything but
// directories and regular files. A name that root does not hold fails with
// an error wrapping fs.ErrNotExist.
func List(root *os.Root, name string) ([]File, error) {
	var files []File
	err := fs.WalkDir(root.FS(), rootName(name), func(stored string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		virtual, ok := virtualPath(stored)
		if !ok || !d.IsDir() && !d.Type().IsRegular() {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		f := File{Path: virtual, Dir: d.IsDir(), Mode: info.Mode().Perm(), ModTime: info.ModTime()}
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

// virtualPath returns the clean absolute path whose stored name is stored,
// relative to the root, and false if the backend cannot have given it.
func virtualPath(stored string) (string, bool) {
	if stored == "." {
		return "/", true
	}
	segments := strings.Split(stored, "/")
	for i, s := range segments {
		name, ok := decodeName(s)
		// A name copied in by hand could decode to one no client can give.
		if !ok || name == "" || name == "." || name == ".." || strings.Contains(name, "/") {
			return "", false
		}
		segments[i] = name
	}
	return path.Join(append([]string{"/"}, segments...)...), true
}
