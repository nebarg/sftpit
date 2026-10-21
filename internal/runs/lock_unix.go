//go:build unix

package runs

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

var errLocked = errors.New("runs: file locked")

// lockFile takes an exclusive lock on f, which lasts until f is closed or
// the process ends, or returns errLocked if another holds one.
func lockFile(f *os.File) error {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) {
		return errLocked
	}
	return err
}
