package backend_test

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/pkg/sftp"

	"sftpit/internal/backend"
	"sftpit/internal/sftpwire"
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
	assertFile(t, outside, "outside the root")
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
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no Unix permission bits")
	}
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
	if info, err := os.Stat(host); err != nil || !info.ModTime().Equal(mtime) {
		t.Errorf("mtime after Chtimes = %v, %v; want %v", info.ModTime(), err, mtime)
	}

	assertStatus(t, c.Chown("/orders.csv", 0, 0), sftpwire.StatusPermissionDenied)
	assertStatus(t, c.Truncate("/missing.csv", 0), sftpwire.StatusNoSuchFile)
}

func TestSetstatAttemptsEveryAttribute(t *testing.T) {
	dir, e := newBackend(t)
	writeHostFile(t, filepath.Join(dir, "orders.csv"), "0123456789")
	s := startRaw(t, e)

	s.wantStatus(&sftpwire.SetStat{Path: "/orders.csv", Attrs: sftpwire.Attrs{
		Flags: sftpwire.AttrUIDGID | sftpwire.AttrSize,
		Size:  2,
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

func TestVersionAdvertisesOnlyPosixRename(t *testing.T) {
	_, e := newBackend(t)
	s := startRaw(t, e)

	want := []sftpwire.Extension{{Name: sftpwire.ExtPosixRename, Data: "1"}}
	if !slices.Equal(s.version.Extensions, want) {
		t.Errorf("extensions = %v, want %v", s.version.Extensions, want)
	}
}

func TestStatusesCarryOpenSSHMessages(t *testing.T) {
	dir, e := newBackend(t)
	s := startRaw(t, e)

	reply := s.wantStatus(&sftpwire.Stat{Path: "/missing/orders.csv"}, sftpwire.StatusNoSuchFile)
	if reply.Message != "No such file" {
		t.Errorf("message = %q, want %q", reply.Message, "No such file")
	}
	writeHostFile(t, filepath.Join(dir, "orders.csv"), "data")
	reply = s.wantStatus(&sftpwire.Stat{Path: "/orders.csv/inner"}, sftpwire.StatusNoSuchFile)
	if reply.Message != "No such file" {
		t.Errorf("message for a file used as a directory = %q, want %q", reply.Message, "No such file")
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

func newBackend(t *testing.T) (string, *backend.Embedded) {
	t.Helper()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() { root.Close() })
	return dir, backend.New(root)
}

func newClient(t *testing.T, e *backend.Embedded, home string) *sftp.Client {
	t.Helper()
	conn := e.Open(home)
	c, err := sftp.NewClientPipe(conn, conn, sftp.UseConcurrentWrites(true))
	if err != nil {
		t.Fatalf("NewClientPipe: %v", err)
	}
	t.Cleanup(func() {
		c.Close()
		if err := conn.Close(); err != nil {
			t.Errorf("backend session: %v", err)
		}
	})
	return c
}

// rawSession speaks the protocol directly, for requests pkg/sftp's client
// cannot send or would retry differently.
type rawSession struct {
	t       *testing.T
	conn    io.ReadWriteCloser
	in      *bufio.Reader
	version sftpwire.Version
	nextID  uint32
}

func startRaw(t *testing.T, e *backend.Embedded) *rawSession {
	t.Helper()
	conn := e.Open("/")
	t.Cleanup(func() { conn.Close() })
	s := &rawSession{t: t, conn: conn, in: bufio.NewReader(conn)}
	if _, err := conn.Write(sftpwire.AppendInit(nil, sftpwire.Init{Version: 3})); err != nil {
		t.Fatalf("write INIT: %v", err)
	}
	b := s.read()
	v, err := sftpwire.DecodeVersion(b)
	if err != nil {
		t.Fatalf("DecodeVersion: %v", err)
	}
	s.version = v
	return s
}

func (s *rawSession) read() []byte {
	s.t.Helper()
	b, err := sftpwire.ReadPacket(s.in, 256*1024)
	if err != nil {
		s.t.Fatalf("ReadPacket: %v", err)
	}
	return b
}

func (s *rawSession) wantStatus(p sftpwire.Packet, want sftpwire.StatusCode) *sftpwire.StatusReply {
	s.t.Helper()
	s.nextID++
	if _, err := s.conn.Write(sftpwire.AppendPacket(nil, s.nextID, p)); err != nil {
		s.t.Fatalf("write %v: %v", p.Type(), err)
	}
	id, reply, err := sftpwire.DecodeReply(s.read())
	if err != nil {
		s.t.Fatalf("DecodeReply: %v", err)
	}
	st, ok := reply.(*sftpwire.StatusReply)
	if id != s.nextID || !ok || st.Code != want {
		s.t.Fatalf("%v: reply %d %#v, want %d with %v", p.Type(), id, reply, s.nextID, want)
	}
	return st
}

// assertStatus checks the status behind an error from pkg/sftp's client,
// which reports NO_SUCH_FILE and PERMISSION_DENIED as os.ErrNotExist and
// os.ErrPermission.
func assertStatus(t *testing.T, err error, want sftpwire.StatusCode) {
	t.Helper()
	var got sftpwire.StatusCode
	switch st, ok := errors.AsType[*sftp.StatusError](err); {
	case ok:
		got = sftpwire.StatusCode(st.Code)
	case errors.Is(err, os.ErrNotExist):
		got = sftpwire.StatusNoSuchFile
	case errors.Is(err, os.ErrPermission):
		got = sftpwire.StatusPermissionDenied
	default:
		t.Fatalf("error = %v, want status %v", err, want)
	}
	if got != want {
		t.Fatalf("status = %v (%v), want %v", got, err, want)
	}
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

func writeHostFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertFile(t *testing.T, name, want string) {
	t.Helper()
	got, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if string(got) != want {
		t.Fatalf("%s = %q, want %q", name, got, want)
	}
}

func assertMissing(t *testing.T, name string) {
	t.Helper()
	if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s still exists (Lstat error %v)", name, err)
	}
}
