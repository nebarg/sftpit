package backend

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
)

// ErrUnsupportedFile reports a seed entry that is neither a regular file
// nor a directory, such as a symlink.
var ErrUnsupportedFile = errors.New("only regular files and directories can be seeded")

// Seed copies the directories and regular files under the host directory
// src into the root, keeping their permission bits and modification times.
// The copy is independent of src: later changes on either side do not reach
// the other. Seed is meant for an empty root, so an entry that already
// exists is an error, and so is any other kind of file, such as a symlink.
func (e *Embedded) Seed(src string) error {
	srcRoot, err := os.OpenRoot(src)
	if err != nil {
		return fmt.Errorf("seed: %w", err)
	}
	defer srcRoot.Close()

	// Directories are created writable and get their own mode and time once
	// their contents are in, so a read-only directory can still be filled
	// and copying into it does not change its time.
	var dirs []string
	err = fs.WalkDir(srcRoot.FS(), ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		switch {
		case name == ".":
			return nil
		case d.IsDir():
			dirs = append(dirs, name)
			return e.root.Mkdir(seedName(name), 0o700)
		case d.Type().IsRegular():
			return e.seedFile(srcRoot, name)
		}
		return fmt.Errorf("%s: %w", filepath.Join(src, filepath.FromSlash(name)), ErrUnsupportedFile)
	})
	if err != nil {
		return fmt.Errorf("seed: %w", err)
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := e.copyMetadata(srcRoot, dirs[i]); err != nil {
			return fmt.Errorf("seed: %w", err)
		}
	}
	return nil
}

func (e *Embedded) seedFile(srcRoot *os.Root, name string) error {
	in, err := srcRoot.Open(name)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := e.root.OpenFile(seedName(name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return e.copyMetadata(srcRoot, name)
}

func (e *Embedded) copyMetadata(srcRoot *os.Root, name string) error {
	info, err := srcRoot.Lstat(name)
	if err != nil {
		return err
	}
	dst := seedName(name)
	if err := e.root.Chmod(dst, permissions(uint32(info.Mode().Perm()))); err != nil {
		return err
	}
	return e.root.Chtimes(dst, info.ModTime(), info.ModTime())
}

// seedName converts a slash-separated name under the seed directory into a
// name under the root, through the same mapping as client paths.
func seedName(name string) string {
	return rootName(path.Join("/", name))
}
