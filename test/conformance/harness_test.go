// Package conformance sends the same requests to sftpit's embedded backend
// and to OpenSSH's sftp-server, and requires the same replies and the same
// resulting files, apart from the differences it lists. It compares with
// sftp-server on Linux, because that is what partners run, and skips
// elsewhere.
package conformance

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/backend"
	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

// sftpServerPaths are where Linux distributions install OpenSSH's
// sftp-server.
var sftpServerPaths = []string{
	"/usr/lib/openssh/sftp-server",     // Debian, Ubuntu
	"/usr/libexec/openssh/sftp-server", // Fedora, RHEL
	"/usr/lib/ssh/sftp-server",         // Alpine, Arch
}

// sftpServer returns the path of OpenSSH's sftp-server, or skips the test
// when there is none to compare with.
func sftpServer(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("compares with OpenSSH's sftp-server on Linux")
	}
	for _, name := range sftpServerPaths {
		if _, err := os.Stat(name); err == nil {
			return name
		}
	}
	t.Skip("OpenSSH's sftp-server is not installed")
	return ""
}

// target is one of the servers being compared, serving the files in dir.
type target struct {
	name string
	dir  string
	open func() io.ReadWriteCloser
}

// sftpitTarget serves from the embedded backend, through the proxy as
// sftpit serve does when proxied is true.
func sftpitTarget(t *testing.T, proxied bool) *target {
	t.Helper()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	limits := backend.Limits{
		MaxFileBytes:  config.DefaultMaxFileBytes,
		MaxTotalBytes: config.DefaultMaxTotalBytes,
		MaxFiles:      config.DefaultMaxFiles,
		MaxOpenFiles:  config.DefaultMaxOpenFiles,
	}
	e, err := backend.New(root, backend.Options{Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	if !proxied {
		return &target{name: "sftpit", dir: dir, open: func() io.ReadWriteCloser { return e.Open("/") }}
	}
	return &target{name: "sftpit through the proxy", dir: dir, open: func() io.ReadWriteCloser {
		client, proxy := net.Pipe()
		c := &proxiedConn{Conn: client, served: make(chan error, 1)}
		go func() {
			c.served <- sftpproxy.Serve(context.Background(), proxy, e.Open("/"), sftpproxy.Options{Logger: slog.New(slog.DiscardHandler)})
		}()
		return c
	}}
}

// proxiedConn is a client's end of a session through the proxy. Closing it
// ends the session and waits for the proxy to finish with it.
type proxiedConn struct {
	net.Conn
	served chan error
}

func (c *proxiedConn) Close() error {
	c.Conn.Close()
	return <-c.served
}

// openSSHTarget runs sftp-server in dir, which it is not confined to, so
// scripts use only paths relative to it.
func openSSHTarget(t *testing.T, server string) *target {
	t.Helper()
	dir := t.TempDir()
	return &target{name: "OpenSSH", dir: dir, open: func() io.ReadWriteCloser {
		cmd := exec.Command(server)
		cmd.Dir = dir
		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatalf("start %s: %v", server, err)
		}
		return &process{Reader: stdout, WriteCloser: stdin, cmd: cmd}
	}}
}

// process is a server's end of a session over its standard input and
// output. Closing it ends the session and waits for the server to exit.
type process struct {
	io.Reader
	io.WriteCloser
	cmd *exec.Cmd
}

func (p *process) Close() error {
	p.WriteCloser.Close()
	return p.cmd.Wait()
}

// session speaks the protocol to one target, naming each handle by the step
// that opened it.
type session struct {
	t       *testing.T
	target  *target
	conn    io.ReadWriteCloser
	in      *bufio.Reader
	version sftpwire.Version
	nextID  uint32
	handles map[string]string
}

func startSession(t *testing.T, target *target) *session {
	t.Helper()
	conn := target.open()
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("%s: end the session: %v", target.name, err)
		}
	})
	s := &session{t: t, target: target, conn: conn, in: bufio.NewReader(conn), handles: make(map[string]string)}
	if _, err := conn.Write(sftpwire.AppendInit(nil, sftpwire.Init{Version: 3})); err != nil {
		t.Fatalf("%s: write INIT: %v", target.name, err)
	}
	v, err := sftpwire.DecodeVersion(s.read())
	if err != nil {
		t.Fatalf("%s: DecodeVersion: %v", target.name, err)
	}
	s.version = v
	return s
}

func (s *session) read() []byte {
	s.t.Helper()
	b, err := sftpwire.ReadPacket(s.in, 256*1024)
	if err != nil {
		s.t.Fatalf("%s: ReadPacket: %v", s.target.name, err)
	}
	return b
}

// send sends p and returns the reply.
func (s *session) send(p sftpwire.Packet) sftpwire.Packet {
	s.t.Helper()
	s.nextID++
	if _, err := s.conn.Write(sftpwire.AppendPacket(nil, s.nextID, p)); err != nil {
		s.t.Fatalf("%s: write %v: %v", s.target.name, p.Type(), err)
	}
	id, reply, err := sftpwire.DecodeReply(s.read())
	if err != nil {
		s.t.Fatalf("%s: DecodeReply: %v", s.target.name, err)
	}
	if id != s.nextID {
		s.t.Fatalf("%s: reply to request %d, want %d", s.target.name, id, s.nextID)
	}
	return reply
}

// stamp is the modification time scripts set, which replies show exactly.
// Other times are recent and differ between the servers, so replies only
// say so.
var stamp = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

// outcome describes how a server answered one request. The longnames of a
// NAME reply, which are for display, are described apart from the rest of
// the reply, so that a difference in them hides nothing else.
type outcome struct {
	reply     string
	longnames string
}

// describe describes reply to request in the terms that both servers
// should agree on.
func (s *session) describe(request, reply sftpwire.Packet) outcome {
	switch r := reply.(type) {
	case *sftpwire.StatusReply:
		return outcome{reply: fmt.Sprintf("%v %q", r.Code, r.Message)}
	case *sftpwire.HandleReply:
		return outcome{reply: "handle"}
	case *sftpwire.DataReply:
		return outcome{reply: fmt.Sprintf("data %q", r.Data)}
	case *sftpwire.AttrsReply:
		return outcome{reply: "attrs " + describeAttrs(r.Attrs)}
	case *sftpwire.ExtendedReply:
		return outcome{reply: fmt.Sprintf("extended reply of %d bytes", len(r.Data))}
	case *sftpwire.NameReply:
		entries := r.Entries
		if _, ok := request.(*sftpwire.ReadDir); ok {
			entries = slices.SortedFunc(slices.Values(entries), func(a, b sftpwire.NameEntry) int {
				return strings.Compare(a.Filename, b.Filename)
			})
		}
		var names, longnames []string
		for _, e := range entries {
			names = append(names, fmt.Sprintf("%q %s", s.relative(e.Filename), describeAttrs(e.Attrs)))
			longname := s.relative(e.Longname)
			if e.Attrs.MTime != uint32(stamp.Unix()) {
				longname = recentDate.ReplaceAllString(longname, "<recent>")
			}
			longnames = append(longnames, fmt.Sprintf("%q", longname))
		}
		return outcome{reply: "names " + strings.Join(names, ", "), longnames: strings.Join(longnames, ", ")}
	}
	return outcome{reply: fmt.Sprintf("%T", reply)}
}

// relative turns a path under the target's directory, as sftp-server's
// REALPATH gives it, into the absolute path sftpit gives.
func (s *session) relative(name string) string {
	dir, err := filepath.EvalSymlinks(s.target.dir)
	if err != nil {
		s.t.Fatal(err)
	}
	if name == dir {
		return "/"
	}
	if rest, ok := strings.CutPrefix(name, dir+"/"); ok {
		return "/" + rest
	}
	return name
}

// recentDate matches the date in a longname for a recent time, which the
// servers can give a minute apart.
var recentDate = regexp.MustCompile(`[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}`)

func describeAttrs(a sftpwire.Attrs) string {
	parts := []string{fmt.Sprintf("flags=%#x", a.Flags)}
	if a.Flags&sftpwire.AttrSize != 0 {
		parts = append(parts, fmt.Sprintf("size=%d", a.Size))
	}
	if a.Flags&sftpwire.AttrUIDGID != 0 {
		parts = append(parts, fmt.Sprintf("uid=%d gid=%d", a.UID, a.GID))
	}
	if a.Flags&sftpwire.AttrPermissions != 0 {
		parts = append(parts, fmt.Sprintf("mode=%#o", a.Permissions))
	}
	if a.Flags&sftpwire.AttrACModTime != 0 {
		mtime := time.Unix(int64(a.MTime), 0)
		switch {
		case mtime.Equal(stamp):
			parts = append(parts, "mtime="+stamp.Format(time.RFC3339))
		case time.Since(mtime).Abs() < time.Hour:
			parts = append(parts, "mtime=recent")
		default:
			parts = append(parts, "mtime="+mtime.UTC().Format(time.RFC3339))
		}
	}
	return strings.Join(parts, " ")
}

// tree lists every file and directory a new session on target finds, with
// each file's size and SHA-256.
func tree(t *testing.T, target *target) []string {
	t.Helper()
	s := startSession(t, target)
	var entries []string
	var walk func(dir string)
	walk = func(dir string) {
		opened, ok := s.send(&sftpwire.OpenDir{Path: dir}).(*sftpwire.HandleReply)
		if !ok {
			t.Fatalf("%s: OPENDIR %s failed", target.name, dir)
		}
		var names []sftpwire.NameEntry
		for {
			reply, ok := s.send(&sftpwire.ReadDir{Handle: opened.Handle}).(*sftpwire.NameReply)
			if !ok {
				break
			}
			names = append(names, reply.Entries...)
		}
		s.send(&sftpwire.Close{Handle: opened.Handle})
		for _, e := range names {
			name := path.Join(dir, e.Filename)
			mode := os.FileMode(e.Attrs.Permissions & 0o777)
			switch {
			case e.Filename == "." || e.Filename == "..":
			case e.Attrs.Permissions&0o170000 == 0o040000:
				entries = append(entries, fmt.Sprintf("%s/ %v", name, mode))
				walk(name)
			default:
				entries = append(entries, fmt.Sprintf("%s %v size=%d sha256=%x", name, mode, e.Attrs.Size, sha256.Sum256(s.readFile(name))))
			}
		}
	}
	walk(".")
	slices.Sort(entries)
	return entries
}

func (s *session) readFile(name string) []byte {
	s.t.Helper()
	opened, ok := s.send(&sftpwire.Open{Path: name, Flags: sftpwire.OpenRead}).(*sftpwire.HandleReply)
	if !ok {
		s.t.Fatalf("%s: OPEN %s failed", s.target.name, name)
	}
	var content []byte
	for {
		data, ok := s.send(&sftpwire.Read{Handle: opened.Handle, Offset: uint64(len(content)), Length: 32 << 10}).(*sftpwire.DataReply)
		if !ok {
			break
		}
		content = append(content, data.Data...)
	}
	s.send(&sftpwire.Close{Handle: opened.Handle})
	return content
}
