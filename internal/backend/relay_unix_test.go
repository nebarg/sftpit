//go:build unix

package backend_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/nebarg/sftpit/internal/sftpwire"
)

// TestCreatesGetThePermissionsTheyAskFor clears the umask, so that each mode
// is exactly what the backend asked the host for, whatever the umask of the
// machine running the tests.
func TestCreatesGetThePermissionsTheyAskFor(t *testing.T) {
	umask := syscall.Umask(0)
	t.Cleanup(func() { syscall.Umask(umask) })
	dir, e := newBackend(t)
	writeHostFile(t, filepath.Join(dir, "existing.csv"), "data")
	existing := hostMode(t, filepath.Join(dir, "existing.csv"))

	s := startRaw(t, e)
	create := func(name string, attrs sftpwire.Attrs) {
		handle := s.handle(&sftpwire.Open{Path: name, Flags: sftpwire.OpenWrite | sftpwire.OpenCreate, Attrs: attrs})
		s.wantStatus(&sftpwire.Close{Handle: handle}, sftpwire.StatusOK)
	}
	create("/private.csv", withPermissions(0o600))
	create("/setuid.sh", withPermissions(0o4755))
	s.wantStatus(&sftpwire.Mkdir{Path: "/private", Attrs: withPermissions(0o700)}, sftpwire.StatusOK)
	s.wantStatus(&sftpwire.Mkdir{Path: "/setuid", Attrs: withPermissions(0o4755)}, sftpwire.StatusOK)
	// A request that asks for no permissions gets the default, whatever the
	// one before it asked for.
	create("/default.csv", sftpwire.Attrs{})
	s.wantStatus(&sftpwire.Mkdir{Path: "/default"}, sftpwire.StatusOK)
	create("/existing.csv", withPermissions(0o600))

	for name, want := range map[string]os.FileMode{
		"private.csv":  0o600,
		"setuid.sh":    0o755,
		"private":      0o700,
		"setuid":       0o755,
		"default.csv":  0o666,
		"default":      0o777,
		"existing.csv": existing,
	} {
		if got := hostMode(t, filepath.Join(dir, name)); got != want {
			t.Errorf("%s has mode %v, want %v", name, got, want)
		}
	}
}

func withPermissions(mode uint32) sftpwire.Attrs {
	return sftpwire.Attrs{Flags: sftpwire.AttrPermissions, Permissions: mode}
}

// hostMode returns the permissions and special bits of the file name.
func hostMode(t *testing.T, name string) os.FileMode {
	t.Helper()
	info, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode() &^ os.ModeType
}
