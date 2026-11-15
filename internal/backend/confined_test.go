package backend_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/pkg/sftp"

	"github.com/nebarg/sftpit/internal/backend"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

// newConfinedBackend returns a backend whose tree holds the home of user foo
// and, outside it, the home of bar and a file at the top.
func newConfinedBackend(t *testing.T, opts backend.Options) (string, *backend.Embedded) {
	t.Helper()
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"home/foo/":           "",
		"home/bar/theirs.txt": "bar's",
		"top.txt":             "top",
	})
	return dir, newBackendIn(t, dir, opts)
}

func names(t *testing.T, c *sftp.Client, dir string) []string {
	t.Helper()
	infos, err := c.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir %s: %v", dir, err)
	}
	var got []string
	for _, info := range infos {
		got = append(got, info.Name())
	}
	slices.Sort(got)
	return got
}

func TestConfinedSessionSeesItsDirectoryAsTheRoot(t *testing.T) {
	dir, e := newConfinedBackend(t, backend.Options{Limits: roomy})
	c := newConfinedClient(t, e, "/", "/home/foo")

	if wd, err := c.Getwd(); err != nil || wd != "/" {
		t.Errorf("Getwd = %q, %v; want /", wd, err)
	}
	for name, want := range map[string]string{".": "/", "/": "/", "..": "/", "/../..": "/", "upload": "/upload", "/upload/../../x": "/x"} {
		if got, err := c.RealPath(name); err != nil || got != want {
			t.Errorf("RealPath(%q) = %q, %v; want %q", name, got, err, want)
		}
	}

	mkdirRemote(t, c, "/upload")
	writeRemote(t, c, "/upload/a.csv", "rows")
	assertFile(t, filepath.Join(dir, "home", "foo", "upload", "a.csv"), "rows")
	assertMissing(t, filepath.Join(dir, "upload"))
	for _, listed := range []string{"/", "/..", "."} {
		if got := names(t, c, listed); !slices.Equal(got, []string{"upload"}) {
			t.Errorf("ReadDir(%q) = %v, want [upload]", listed, got)
		}
	}
}

func TestConfinedSessionStartsInItsHome(t *testing.T) {
	_, e := newConfinedBackend(t, backend.Options{Limits: roomy})
	c := newConfinedClient(t, e, "/", "/home/foo")
	mkdirRemote(t, c, "/in")
	c = newConfinedClient(t, e, "/in", "/home/foo")
	if wd, err := c.Getwd(); err != nil || wd != "/in" {
		t.Errorf("Getwd = %q, %v; want /in", wd, err)
	}
}

func TestConfinedSessionCannotReachOutsideItsDirectory(t *testing.T) {
	dir, e := newConfinedBackend(t, backend.Options{Limits: roomy})
	outside := filepath.Join(t.TempDir(), "secret.txt")
	writeHostFile(t, outside, "secret")
	home := filepath.Join(dir, "home", "foo")
	for link, target := range map[string]string{"file-link": outside, "dir-link": filepath.Dir(outside), "up-link": "../bar/theirs.txt"} {
		if err := os.Symlink(target, filepath.Join(home, link)); err != nil {
			t.Skipf("cannot create a symlink here: %v", err)
		}
	}
	c := newConfinedClient(t, e, "/", "/home/foo")
	writeRemote(t, c, "/mine.txt", "mine")

	// A path that names another user's home or the top of the tree is a
	// path in the user's own view, which does not hold it, and the dot-dot
	// segments are cleaned away before the backend sees them.
	for _, name := range []string{"/home/bar/theirs.txt", "/top.txt", "/../top.txt", "/../bar/theirs.txt", "../../home/bar/theirs.txt"} {
		_, err := c.Open(name)
		assertStatus(t, err, sftpwire.StatusNoSuchFile)
		_, err = c.Stat(name)
		assertStatus(t, err, sftpwire.StatusNoSuchFile)
		_, err = c.Lstat(name)
		assertStatus(t, err, sftpwire.StatusNoSuchFile)
		assertStatus(t, c.Remove(name), sftpwire.StatusNoSuchFile)
		assertStatus(t, c.Rename(name, "/stolen.txt"), sftpwire.StatusNoSuchFile)
		assertStatus(t, c.PosixRename(name, "/stolen.txt"), sftpwire.StatusNoSuchFile)
	}
	for _, name := range []string{"/home/bar", "/home"} {
		_, err := c.ReadDir(name)
		assertStatus(t, err, sftpwire.StatusNoSuchFile)
	}
	_, err := c.Create("/home/bar/new.txt")
	assertStatus(t, err, sftpwire.StatusNoSuchFile)
	assertStatus(t, c.Mkdir("/home/bar/new"), sftpwire.StatusNoSuchFile)
	assertStatus(t, c.Rename("/mine.txt", "/home/bar/mine.txt"), sftpwire.StatusNoSuchFile)
	assertStatus(t, c.PosixRename("/mine.txt", "/home/bar/mine.txt"), sftpwire.StatusNoSuchFile)
	assertStatus(t, c.Rename("/mine.txt", outside), sftpwire.StatusNoSuchFile)
	assertStatus(t, c.PosixRename("/mine.txt", outside), sftpwire.StatusNoSuchFile)
	assertFile(t, filepath.Join(home, "mine.txt"), "mine")

	// A symlink put there by hand is not followed out of the directory.
	for _, name := range []string{"/file-link", "/up-link", "/dir-link/secret.txt"} {
		f, err := c.Open(name)
		if err == nil {
			f.Close()
			t.Fatalf("Open(%s) followed a symlink out of the directory", name)
		}
		assertStatus(t, err, sftpwire.StatusFailure)
		_, err = c.Stat(name)
		assertStatus(t, err, sftpwire.StatusFailure)
		_, err = c.OpenFile(name, os.O_WRONLY|os.O_TRUNC)
		assertStatus(t, err, sftpwire.StatusFailure)
	}
	_, err = c.ReadDir("/dir-link")
	assertStatus(t, err, sftpwire.StatusFailure)
	assertStatus(t, c.Rename("/mine.txt", "/dir-link/mine.txt"), sftpwire.StatusFailure)

	assertFile(t, outside, "secret")
	assertFile(t, filepath.Join(dir, "home", "bar", "theirs.txt"), "bar's")
	assertFile(t, filepath.Join(dir, "top.txt"), "top")
	assertMissing(t, filepath.Join(filepath.Dir(outside), "mine.txt"))
	assertMissing(t, filepath.Join(dir, "home", "bar", "mine.txt"))
	assertMissing(t, filepath.Join(home, "stolen.txt"))
}

func TestConfinedSessionRenamesWithinItsDirectory(t *testing.T) {
	dir, e := newConfinedBackend(t, backend.Options{Limits: roomy})
	c := newConfinedClient(t, e, "/", "/home/foo")
	writeRemote(t, c, "/a.txt", "a")

	// Dot-dot segments at the top stay at the top, so this is a path in
	// the directory, not above it.
	if err := c.PosixRename("/a.txt", "/../../b.txt"); err != nil {
		t.Fatalf("PosixRename: %v", err)
	}
	assertFile(t, filepath.Join(dir, "home", "foo", "b.txt"), "a")
	assertMissing(t, filepath.Join(dir, "b.txt"))
}

func TestRunFileLimitCountsConfinedAndSharedSessionsTogether(t *testing.T) {
	// The tree holds five files and directories: home, home/foo, home/bar,
	// bar's file and top.txt.
	limits := backend.Limits{MaxFileBytes: 10, MaxTotalBytes: 100, MaxFiles: 7, MaxOpenFiles: 10}
	_, e := newConfinedBackend(t, backend.Options{Limits: limits})
	confined := newConfinedClient(t, e, "/", "/home/foo")
	shared := newClient(t, e, "/")

	writeRemote(t, confined, "/a", "")
	writeRemote(t, shared, "/b", "")
	assertStatus(t, confined.Mkdir("/c"), sftpwire.StatusFailure)
	assertStatus(t, writeAt(shared, "/c", "", 0, os.O_CREATE), sftpwire.StatusFailure)

	if err := confined.Remove("/a"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	writeRemote(t, shared, "/c", "")
	assertStatus(t, writeAt(confined, "/d", "", 0, os.O_CREATE), sftpwire.StatusFailure)

	if err := shared.Remove("/c"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	mkdirRemote(t, confined, "/d")
}

func TestRunByteLimitCountsConfinedAndSharedSessionsTogether(t *testing.T) {
	// bar's file and top.txt hold eight bytes.
	limits := backend.Limits{MaxFileBytes: 10, MaxTotalBytes: 20, MaxFiles: 100, MaxOpenFiles: 10}
	_, e := newConfinedBackend(t, backend.Options{Limits: limits})
	confined := newConfinedClient(t, e, "/", "/home/foo")
	shared := newClient(t, e, "/")

	if err := writeAt(confined, "/a", "012345", 0, os.O_CREATE); err != nil {
		t.Fatalf("confined write: %v", err)
	}
	if err := writeAt(shared, "/b", "012345", 0, os.O_CREATE); err != nil {
		t.Fatalf("shared write: %v", err)
	}
	assertStatus(t, writeAt(confined, "/a", "!", 6, 0), sftpwire.StatusFailure)
	assertStatus(t, writeAt(shared, "/b", "!", 6, 0), sftpwire.StatusFailure)

	if err := confined.Remove("/a"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := writeAt(shared, "/b", "6789", 6, 0); err != nil {
		t.Fatalf("shared write after the remove: %v", err)
	}
	if err := writeAt(confined, "/c", "01", 0, os.O_CREATE); err != nil {
		t.Fatalf("confined write after the remove: %v", err)
	}
	assertStatus(t, writeAt(confined, "/c", "!", 2, 0), sftpwire.StatusFailure)
}

func TestConfinedSessionFailsWhenItsDirectoryIsMissing(t *testing.T) {
	_, e := newConfinedBackend(t, backend.Options{Limits: roomy})
	conn := e.Open("/", "/home/gone")
	if err := conn.Close(); err == nil {
		t.Fatal("a session confined to a missing directory ended without an error")
	}
}
