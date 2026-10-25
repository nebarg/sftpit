package backend_test

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkg/sftp"

	"github.com/nebarg/sftpit/internal/backend"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

// roomy are limits that no test reaches unless it means to.
var roomy = backend.Limits{MaxFileBytes: 1 << 30, MaxTotalBytes: 1 << 32, MaxFiles: 1 << 20, MaxOpenFiles: 1 << 10}

// tight are limits small enough for a test to reach each one.
var tight = backend.Limits{MaxFileBytes: 10, MaxTotalBytes: 25, MaxFiles: 4, MaxOpenFiles: 2}

func newBackend(t *testing.T) (string, *backend.Embedded) {
	t.Helper()
	dir := t.TempDir()
	return dir, newBackendIn(t, dir, backend.Options{Limits: roomy})
}

// newBackendIn returns a backend with opts that serves the files in dir.
func newBackendIn(t *testing.T, dir string, opts backend.Options) *backend.Embedded {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() { root.Close() })
	e, err := backend.New(root, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
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

func (s *rawSession) read() []byte {
	s.t.Helper()
	b, err := sftpwire.ReadPacket(s.in, 256*1024)
	if err != nil {
		s.t.Fatalf("ReadPacket: %v", err)
	}
	return b
}

// send sends p and returns the reply.
func (s *rawSession) send(p sftpwire.Packet) sftpwire.Packet {
	s.t.Helper()
	s.nextID++
	if _, err := s.conn.Write(sftpwire.AppendPacket(nil, s.nextID, p)); err != nil {
		s.t.Fatalf("write %v: %v", p.Type(), err)
	}
	id, reply, err := sftpwire.DecodeReply(s.read())
	if err != nil {
		s.t.Fatalf("DecodeReply: %v", err)
	}
	if id != s.nextID {
		s.t.Fatalf("%v: reply to request %d, want %d", p.Type(), id, s.nextID)
	}
	return reply
}

func (s *rawSession) wantStatus(p sftpwire.Packet, want sftpwire.StatusCode) *sftpwire.StatusReply {
	s.t.Helper()
	reply := s.send(p)
	st, ok := reply.(*sftpwire.StatusReply)
	if !ok || st.Code != want {
		s.t.Fatalf("%v: reply %#v, want %v", p.Type(), reply, want)
	}
	return st
}

// handle sends an OPEN or OPENDIR and returns the handle it opens.
func (s *rawSession) handle(p sftpwire.Packet) string {
	s.t.Helper()
	reply, ok := s.send(p).(*sftpwire.HandleReply)
	if !ok {
		s.t.Fatalf("%v: reply %#v, want a handle", p.Type(), reply)
	}
	return reply.Handle
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

// writeAt opens the file at name for writing, adding flag, writes s at off
// and closes the file, returning the write's error.
func writeAt(c *sftp.Client, name, s string, off int64, flag int) error {
	f, err := c.OpenFile(name, os.O_WRONLY|flag)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteAt([]byte(s), off)
	return err
}

// writeTree writes files under dir, where a name ending in a slash is a
// directory.
func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		if strings.HasSuffix(name, "/") {
			if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		writeHostFile(t, filepath.Join(dir, name), content)
	}
}
