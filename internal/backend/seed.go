package backend

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
)

// ErrUnsupportedFile reports a seed entry that is neither a regular file
// nor a directory, such as a symlink.
var ErrUnsupportedFile = errors.New("only regular files and directories can be seeded")

// Seed copies the directories and regular files under the host directory
// src into the root, keeping their permission bits and modification times.
// The copy is independent of src: later changes on either side do not reach
// the other. Seed is meant for an empty root, so an entry that already
// exists is an error, and so is any other kind of file, such as a symlink.
// The copy counts towards the limits, and an entry that would take the files
// past one is an error wrapping ErrLimit.
func (e *Embedded) Seed(src string) error {
	srcRoot, err := os.OpenRoot(src)
	if err != nil {
		return fmt.Errorf("backend: seed: %w", err)
	}
	defer srcRoot.Close()

	// Directories are created writable and get their own mode and time once
	// their contents are in, so a read-only directory can still be filled
	// and copying into it does not change its time.
	var dirs []string
	err = fs.WalkDir(srcRoot.FS(), ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || name == "." {
			return err
		}
		switch {
		case d.IsDir():
			dirs = append(dirs, name)
			err = e.seedDir(name)
		case d.Type().IsRegular():
			err = e.seedFile(srcRoot, name)
		default:
			err = ErrUnsupportedFile
		}
		if err != nil {
			return fmt.Errorf("%s: %w", filepath.Join(src, filepath.FromSlash(name)), err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("backend: seed: %w", err)
	}
	for _, dir := range slices.Backward(dirs) {
		if err := e.copyMetadata(srcRoot, dir); err != nil {
			return fmt.Errorf("backend: seed: %w", err)
		}
	}
	return nil
}

func (e *Embedded) seedDir(name string) error {
	virtual := seedPath(name)
	defer e.usage.change(virtual)()
	if limit := e.usage.limitOnCreate(virtual); limit != nil {
		return limit
	}
	return e.root.Mkdir(rootName(virtual), 0o700)
}

func (e *Embedded) seedFile(srcRoot *os.Root, name string) error {
	in, err := srcRoot.Open(name)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := e.copyIn(in, seedPath(name)); err != nil {
		return err
	}
	return e.copyMetadata(srcRoot, name)
}

// copyIn copies in to a new file at the virtual path name, unless the file
// would take the files past a limit.
func (e *Embedded) copyIn(in *os.File, name string) error {
	defer e.usage.change(name)()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if limit := e.usage.limitOnCreate(name); limit != nil {
		return limit
	}
	if limit := e.usage.limitOnGrowth(0, info.Size()); limit != nil {
		return limit
	}
	out, err := e.root.OpenFile(rootName(name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	return err
}

func (e *Embedded) copyMetadata(srcRoot *os.Root, name string) error {
	info, err := srcRoot.Lstat(name)
	if err != nil {
		return err
	}
	dst := rootName(seedPath(name))
	if err := e.root.Chmod(dst, permissions(uint32(info.Mode().Perm()))); err != nil {
		return err
	}
	return e.root.Chtimes(dst, info.ModTime(), info.ModTime())
}

// seedPath converts a slash-separated name under the seed directory into
// the virtual path it is copied to.
func seedPath(name string) string {
	return path.Join("/", name)
}
