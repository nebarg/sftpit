package backend_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/sftp"

	"github.com/nebarg/sftpit/internal/sftpwire"
)

func TestTransferRoundTrip(t *testing.T) {
	dir, e := newBackend(t)
	c := newClient(t, e, "/")

	want := make([]byte, 3<<20+17)
	rand.NewChaCha8([32]byte{}).Read(want)
	f, err := c.Create("/orders.bin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := f.ReadFrom(bytes.NewReader(want)); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close upload: %v", err)
	}

	onDisk, err := os.ReadFile(filepath.Join(dir, "orders.bin"))
	if err != nil {
		t.Fatalf("read stored file: %v", err)
	}
	if !bytes.Equal(onDisk, want) {
		t.Fatalf("stored %d bytes that differ from the %d uploaded", len(onDisk), len(want))
	}

	f, err = c.Open("/orders.bin")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	var got bytes.Buffer
	if _, err := f.WriteTo(&got); err != nil {
		t.Fatalf("download: %v", err)
	}
	f.Close()
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("downloaded %d bytes that differ from the %d uploaded", got.Len(), len(want))
	}
}

func TestHomeIsTheDefaultDirectory(t *testing.T) {
	dir, e := newBackend(t)
	if err := e.MkdirAll("/partners/b"); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	c := newClient(t, e, "/partners/b")

	wd, err := c.Getwd()
	if err != nil || wd != "/partners/b" {
		t.Fatalf("Getwd = %q, %v; want /partners/b", wd, err)
	}
	writeRemote(t, c, "orders.csv", "relative")
	assertFile(t, filepath.Join(dir, "partners", "b", "orders.csv"), "relative")
}

func TestPathsStayInsideTheRoot(t *testing.T) {
	dir, e := newBackend(t)
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("outside the root"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "escape")); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}
	c := newClient(t, e, "/")

	writeRemote(t, c, "/../../orders.csv", "cleaned")
	assertFile(t, filepath.Join(dir, "orders.csv"), "cleaned")

	if f, err := c.Open("/escape"); err == nil {
		f.Close()
		t.Fatal("Open followed a symlink out of the root")
	}
	if f, err := c.OpenFile("/escape", os.O_WRONLY|os.O_TRUNC); err == nil {
		f.Close()
		t.Fatal("OpenFile followed a symlink out of the root")
	}
	if info, err := c.Lstat("/escape"); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("Lstat(/escape) = %v, %v; want the symlink itself", info, err)
	}
	assertFile(t, outside, "outside the root")
}

func TestNamesAreStoredAsGiven(t *testing.T) {
	dir, e := newBackend(t)
	c := newClient(t, e, "/")
	mkdirRemote(t, c, "/Incoming")
	names := []string{"Orders 2026.CSV", "café.csv", "日本語.txt", "con.txt", "orders.csv.", `back\slash.txt`, "a:b.csv", "%61^b"}
	for _, name := range names {
		writeRemote(t, c, "/Incoming/"+name, name)
		assertFile(t, filepath.Join(dir, "Incoming", name), name)
	}

	entries, err := c.ReadDir("/Incoming")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var listed []string
	for _, entry := range entries {
		listed = append(listed, entry.Name())
	}
	if want := slices.Sorted(slices.Values(names)); !slices.Equal(slices.Sorted(slices.Values(listed)), want) {
		t.Errorf("listed %q, want %q", listed, want)
	}
	for _, name := range names {
		f, err := c.Open("/Incoming/" + name)
		if err != nil {
			t.Fatalf("Open %s: %v", name, err)
		}
		got, err := io.ReadAll(f)
		f.Close()
		if err != nil || string(got) != name {
			t.Errorf("%s = %q, %v; want its own content", name, got, err)
		}
	}

	if err := e.MkdirAll("/Partner-B/In"); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if info, err := os.Stat(filepath.Join(dir, "Partner-B", "In")); err != nil || !info.IsDir() {
		t.Errorf("MkdirAll did not create the directories under their own names: %v", err)
	}
}

func TestFilesPutInTheDirectoryByHandAreServed(t *testing.T) {
	dir, e := newBackend(t)
	writeHostFile(t, filepath.Join(dir, "Copied In", "Notes.TXT"), "by hand")
	writeHostFile(t, filepath.Join(dir, "%61"), "percent")
	writeHostFile(t, filepath.Join(dir, "^b"), "caret")
	c := newClient(t, e, "/")

	entries, err := c.ReadDir("/")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var got []string
	for _, entry := range entries {
		got = append(got, entry.Name())
	}
	slices.Sort(got)
	if want := []string{"%61", "Copied In", "^b"}; !slices.Equal(got, want) {
		t.Errorf("listed %q, want %q", got, want)
	}
	info, err := c.Stat("/Copied In/Notes.TXT")
	if err != nil || info.Size() != 7 || info.Name() != "Notes.TXT" {
		t.Fatalf("Stat = %v, %v; want the 7-byte file", info, err)
	}
	f, err := c.Open("/Copied In/Notes.TXT")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()
	if b, err := io.ReadAll(f); err != nil || string(b) != "by hand" {
		t.Errorf("read %q, %v; want the file's content", b, err)
	}
}

func TestSymlinksPutInTheDirectoryByHand(t *testing.T) {
	dir, e := newBackend(t)
	writeHostFile(t, filepath.Join(dir, "inside.txt"), "inside")
	if err := os.Symlink("inside.txt", filepath.Join(dir, "inner")); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(dir, "outer")); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, e, "/")

	entries, err := c.ReadDir("/")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var got []string
	for _, entry := range entries {
		got = append(got, entry.Name())
	}
	slices.Sort(got)
	if want := []string{"inner", "inside.txt", "outer"}; !slices.Equal(got, want) {
		t.Errorf("listed %q, want %q", got, want)
	}
	if info, err := c.Lstat("/inner"); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("Lstat(/inner) = %v, %v; want the symlink itself", info, err)
	}
	if info, err := c.Stat("/inner"); err != nil || info.Size() != 6 {
		t.Errorf("Stat(/inner) = %v, %v; want the file it points to inside the root", info, err)
	}
	if _, err := c.Stat("/outer"); err == nil {
		t.Error("Stat followed a symlink out of the root")
	}
	if _, err := c.ReadDir("/outer"); err == nil {
		t.Error("ReadDir followed a symlink out of the root")
	}
}

func TestNamesCannotLeaveTheRoot(t *testing.T) {
	dir, e := newBackend(t)
	outside := t.TempDir()
	writeHostFile(t, filepath.Join(outside, "secret.txt"), "outside")
	c := newClient(t, e, "/")
	mkdirRemote(t, c, "/a")

	// Dot-dot segments are cleaned away before the backend sees a name, and
	// a backslash is an ordinary character in one.
	for name, stored := range map[string]string{
		"/a/../../up.txt":   "up.txt",
		"/../../../up2.txt": "up2.txt",
		"a/../../up3.txt":   "up3.txt",
		"//a///./b.txt":     "a/b.txt",
		`/a/..\..\c.txt`:    `a/..\..\c.txt`,
		`/..\d.txt`:         `..\d.txt`,
	} {
		writeRemote(t, c, name, name)
		assertFile(t, filepath.Join(dir, filepath.FromSlash(stored)), name)
	}

	// An absolute host path is a path under the root, which does not hold it.
	_, err := c.Create(filepath.Join(outside, "new.txt"))
	assertStatus(t, err, sftpwire.StatusNoSuchFile)
	_, err = c.Open(filepath.Join(outside, "secret.txt"))
	assertStatus(t, err, sftpwire.StatusNoSuchFile)
	assertFile(t, filepath.Join(outside, "secret.txt"), "outside")
	assertMissing(t, filepath.Join(outside, "new.txt"))
}

func TestNamesWithANULByteAreABadMessage(t *testing.T) {
	_, e := newBackend(t)
	s := startRaw(t, e)
	s.wantStatus(&sftpwire.Open{Path: "/a\x00b", Flags: sftpwire.OpenWrite | sftpwire.OpenCreate}, sftpwire.StatusBadMessage)
	s.wantStatus(&sftpwire.Mkdir{Path: "/a\x00b"}, sftpwire.StatusBadMessage)
	s.wantStatus(&sftpwire.Remove{Path: "/a\x00b"}, sftpwire.StatusBadMessage)
}

func TestNamesOverTheHostLimitAreABadMessage(t *testing.T) {
	_, e := newBackend(t)
	c := newClient(t, e, "/")
	writeRemote(t, c, "/"+strings.Repeat("n", 255), "fits")
	tooLong := "/" + strings.Repeat("n", 256)
	_, err := c.Create(tooLong)
	assertStatus(t, err, sftpwire.StatusBadMessage)
	assertStatus(t, c.Mkdir(tooLong), sftpwire.StatusBadMessage)
}

func TestNamesThatDifferOnlyInCaseAreDifferentFiles(t *testing.T) {
	skipUnlessCaseSensitive(t)
	_, e := newBackend(t)
	c := newClient(t, e, "/")
	writeRemote(t, c, "/orders.csv", "lower")
	writeRemote(t, c, "/Orders.csv", "capital")
	f, err := c.OpenFile("/ORDERS.CSV", os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		t.Fatalf("exclusive create of a third spelling: %v", err)
	}
	f.Close()

	if err := c.Rename("/Orders.csv", "/OrderS.csv"); err != nil {
		t.Fatalf("rename that changes only case: %v", err)
	}
	for name, want := range map[string]string{"/orders.csv": "lower", "/OrderS.csv": "capital", "/ORDERS.CSV": ""} {
		f, err := c.Open(name)
		if err != nil {
			t.Fatalf("Open %s: %v", name, err)
		}
		got, err := io.ReadAll(f)
		f.Close()
		if err != nil || string(got) != want {
			t.Errorf("%s = %q, %v; want %q", name, got, err, want)
		}
	}
	if _, err := c.Stat("/Orders.csv"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Stat of the renamed file = %v, want it gone", err)
	}
}

func TestStandardRenameRefusesAnExistingTarget(t *testing.T) {
	dir, e := newBackend(t)
	c := newClient(t, e, "/")
	writeRemote(t, c, "/orders.csv", "new")
	writeRemote(t, c, "/published.csv", "old")
	mkdirRemote(t, c, "/in")
	mkdirRemote(t, c, "/out")

	assertStatus(t, c.Rename("/orders.csv", "/published.csv"), sftpwire.StatusFailure)
	assertFile(t, filepath.Join(dir, "orders.csv"), "new")
	assertFile(t, filepath.Join(dir, "published.csv"), "old")

	assertStatus(t, c.Rename("/in", "/out"), sftpwire.StatusFailure)
	assertStatus(t, c.Rename("/in", "/published.csv"), sftpwire.StatusFailure)
	assertStatus(t, c.Rename("/missing.csv", "/other.csv"), sftpwire.StatusNoSuchFile)

	if err := c.Rename("/orders.csv", "/in/orders.csv"); err != nil {
		t.Fatalf("Rename a file to a free name: %v", err)
	}
	assertFile(t, filepath.Join(dir, "in", "orders.csv"), "new")
	assertMissing(t, filepath.Join(dir, "orders.csv"))

	if err := c.Rename("/in", "/archive"); err != nil {
		t.Fatalf("Rename a directory to a free name: %v", err)
	}
	assertFile(t, filepath.Join(dir, "archive", "orders.csv"), "new")
}

func TestPosixRenameReplacesTheTarget(t *testing.T) {
	dir, e := newBackend(t)
	c := newClient(t, e, "/")
	writeRemote(t, c, "/orders.csv", "new")
	writeRemote(t, c, "/published.csv", "old")

	if err := c.PosixRename("/orders.csv", "/published.csv"); err != nil {
		t.Fatalf("PosixRename: %v", err)
	}
	assertFile(t, filepath.Join(dir, "published.csv"), "new")
	assertMissing(t, filepath.Join(dir, "orders.csv"))
}

func TestRemoveAndRmdirOnlyRemoveTheirOwnKind(t *testing.T) {
	dir, e := newBackend(t)
	s := startRaw(t, e)
	writeHostFile(t, filepath.Join(dir, "orders.csv"), "data")
	if err := os.MkdirAll(filepath.Join(dir, "in", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}

	s.wantStatus(&sftpwire.Remove{Path: "/in/nested"}, sftpwire.StatusFailure)
	s.wantStatus(&sftpwire.Rmdir{Path: "/orders.csv"}, sftpwire.StatusNoSuchFile)
	s.wantStatus(&sftpwire.Rmdir{Path: "/in"}, sftpwire.StatusFailure)
	assertFile(t, filepath.Join(dir, "orders.csv"), "data")
	if _, err := os.Stat(filepath.Join(dir, "in", "nested")); err != nil {
		t.Fatalf("directory removed: %v", err)
	}

	s.wantStatus(&sftpwire.Remove{Path: "/orders.csv"}, sftpwire.StatusOK)
	s.wantStatus(&sftpwire.Rmdir{Path: "/in/nested"}, sftpwire.StatusOK)
	assertMissing(t, filepath.Join(dir, "orders.csv"))
	assertMissing(t, filepath.Join(dir, "in", "nested"))
}

func TestAppendWritesAtTheEnd(t *testing.T) {
	dir, e := newBackend(t)
	c := newClient(t, e, "/")
	writeRemote(t, c, "/log.txt", "one ")

	f, err := c.OpenFile("/log.txt", os.O_WRONLY|os.O_APPEND)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	for _, s := range []string{"two ", "three"} {
		if _, err := f.WriteAt([]byte(s), 0); err != nil {
			t.Fatalf("WriteAt: %v", err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	assertFile(t, filepath.Join(dir, "log.txt"), "one two three")
}

// TestAppendsKeepRequestOrder pipelines many appends, which only produce the
// original content if the backend applies them in the order they were sent.
func TestAppendsKeepRequestOrder(t *testing.T) {
	dir, e := newBackend(t)
	c := newClient(t, e, "/")
	want := make([]byte, 2<<20)
	rand.NewChaCha8([32]byte{1}).Read(want)

	f, err := c.OpenFile("/log.bin", os.O_WRONLY|os.O_CREATE|os.O_APPEND)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.ReadFrom(bytes.NewReader(want)); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "log.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("appended %d bytes that differ from the %d sent", len(got), len(want))
	}
}

func TestExclusiveCreateRefusesAnExistingFile(t *testing.T) {
	_, e := newBackend(t)
	c := newClient(t, e, "/")
	writeRemote(t, c, "/orders.csv", "data")

	_, err := c.OpenFile("/orders.csv", os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	assertStatus(t, err, sftpwire.StatusFailure)
}

func TestSetstat(t *testing.T) {
	dir, e := newBackend(t)
	c := newClient(t, e, "/")
	host := filepath.Join(dir, "orders.csv")
	writeRemote(t, c, "/orders.csv", "0123456789")

	if err := c.Truncate("/orders.csv", 4); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	assertFile(t, host, "0123")

	if err := c.Chmod("/orders.csv", 0o640|os.ModeSetuid); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	info, err := os.Stat(host)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode() != 0o640 {
		t.Errorf("mode after Chmod = %v, want -rw-r----- with setuid dropped", info.Mode())
	}

	mtime := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	if err := c.Chtimes("/orders.csv", mtime, mtime); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	switch info, err := os.Stat(host); {
	case err != nil:
		t.Errorf("Stat after Chtimes: %v", err)
	case !info.ModTime().Equal(mtime):
		t.Errorf("mtime after Chtimes = %v, want %v", info.ModTime(), mtime)
	}

	// A client that copies every attribute back sets the owner it was
	// shown, which changes nothing. Any other owner is refused.
	stat, err := c.Stat("/orders.csv")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	owner := stat.Sys().(*sftp.FileStat)
	uid, gid := int(owner.UID), int(owner.GID)
	if err := c.Chown("/orders.csv", uid, gid); err != nil {
		t.Errorf("Chown to the owner: %v", err)
	}
	assertStatus(t, c.Chown("/orders.csv", uid+1, gid), sftpwire.StatusPermissionDenied)
	assertStatus(t, c.Chown("/orders.csv", uid, gid+1), sftpwire.StatusPermissionDenied)
	assertStatus(t, c.Chown("/missing.csv", uid, gid), sftpwire.StatusNoSuchFile)
	assertStatus(t, c.Truncate("/missing.csv", 0), sftpwire.StatusNoSuchFile)
}

func TestSetstatAttemptsEveryAttribute(t *testing.T) {
	dir, e := newBackend(t)
	writeHostFile(t, filepath.Join(dir, "orders.csv"), "0123456789")
	info, err := os.Stat(filepath.Join(dir, "orders.csv"))
	if err != nil {
		t.Fatal(err)
	}
	owner := info.Sys().(*syscall.Stat_t)
	s := startRaw(t, e)

	// Another owner is refused even for root, who could chown(2) the file.
	s.wantStatus(&sftpwire.SetStat{Path: "/orders.csv", Attrs: sftpwire.Attrs{
		Flags: sftpwire.AttrUIDGID | sftpwire.AttrSize,
		Size:  2,
		UID:   owner.Uid + 1,
		GID:   owner.Gid,
	}}, sftpwire.StatusPermissionDenied)
	assertFile(t, filepath.Join(dir, "orders.csv"), "01")
}

func TestLinksAreUnsupported(t *testing.T) {
	dir, e := newBackend(t)
	writeHostFile(t, filepath.Join(dir, "orders.csv"), "data")
	c := newClient(t, e, "/")

	assertStatus(t, c.Symlink("/orders.csv", "/link.csv"), sftpwire.StatusOpUnsupported)
	assertStatus(t, c.Link("/orders.csv", "/link.csv"), sftpwire.StatusOpUnsupported)
	_, err := c.ReadLink("/orders.csv")
	assertStatus(t, err, sftpwire.StatusOpUnsupported)
	assertMissing(t, filepath.Join(dir, "link.csv"))
}

func TestVersionAdvertisesNoLinks(t *testing.T) {
	_, e := newBackend(t)
	s := startRaw(t, e)

	want := []sftpwire.Extension{{Name: sftpwire.ExtPosixRename, Data: "1"}, {Name: sftpwire.ExtStatVFS, Data: "2"}}
	if !slices.Equal(s.version.Extensions, want) {
		t.Errorf("extensions = %v, want %v", s.version.Extensions, want)
	}
}

func TestListing(t *testing.T) {
	dir, e := newBackend(t)
	writeHostFile(t, filepath.Join(dir, "in", "a.csv"), "a")
	writeHostFile(t, filepath.Join(dir, "in", "b.csv"), "bb")
	c := newClient(t, e, "/")

	entries, err := c.ReadDir("/in")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var got []string
	for _, entry := range entries {
		got = append(got, entry.Name())
	}
	slices.Sort(got)
	if want := []string{"a.csv", "b.csv"}; !slices.Equal(got, want) {
		t.Errorf("entries = %v, want %v", got, want)
	}

	_, err = c.ReadDir("/in/a.csv")
	assertStatus(t, err, sftpwire.StatusNoSuchFile)
}

func TestCloseEndsTheSession(t *testing.T) {
	_, e := newBackend(t)
	conn := e.Open("/")
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestCloseReturnsTheErrorTheSessionEndedWith(t *testing.T) {
	t.Run("a packet over the limit", func(t *testing.T) {
		_, e := newBackend(t)
		conn := e.Open("/")
		if _, err := conn.Write(binary.BigEndian.AppendUint32(nil, 1<<20)); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := conn.Close(); err == nil {
			t.Error("Close = nil, want the length limit error")
		}
	})
	t.Run("a request the request server cannot parse", func(t *testing.T) {
		_, e := newBackend(t)
		conn := e.Open("/")
		if _, err := conn.Write(sftpwire.AppendInit(nil, sftpwire.Init{Version: 3})); err != nil {
			t.Fatalf("Write INIT: %v", err)
		}
		if _, err := sftpwire.ReadPacket(conn, 256*1024); err != nil {
			t.Fatalf("reading VERSION: %v", err)
		}
		if _, err := conn.Write([]byte{0, 0, 0, 6, byte(sftpwire.TypeOpen), 0, 0, 0, 1, 0}); err != nil {
			t.Fatalf("Write OPEN: %v", err)
		}
		if err := conn.Close(); err == nil || strings.Contains(err.Error(), "request server ended the session") {
			t.Errorf("Close = %v, want the request server's own error", err)
		}
	})
}

func writeRemote(t *testing.T, c *sftp.Client, name, content string) {
	t.Helper()
	f, err := c.Create(name)
	if err != nil {
		t.Fatalf("Create %s: %v", name, err)
	}
	if _, err := f.Write([]byte(content)); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", name, err)
	}
}

func mkdirRemote(t *testing.T, c *sftp.Client, name string) {
	t.Helper()
	if err := c.Mkdir(name); err != nil {
		t.Fatalf("Mkdir %s: %v", name, err)
	}
}
