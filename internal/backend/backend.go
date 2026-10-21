// Package backend serves SFTP sessions from a directory on the host through
// pkg/sftp's request server. It holds no fault logic: faults are applied by
// the proxy in front of it, so the backend never blocks on one.
//
// Requests behave as they do in OpenSSH's sftp-server: a standard rename
// refuses an existing target while posix-rename replaces it, appends ignore
// the client's offset, and errors map to the same statuses and messages.
// Links are unsupported, and ownership cannot be changed.
//
// The files stay within the backend's Limits. A request that would take them
// past one is refused with SSH_FX_FAILURE, as OpenSSH's sftp-server refuses
// a write to a full disk, and statvfs@openssh.com reports the limits as the
// size of the filesystem.
package backend

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/pkg/sftp"

	"github.com/nebarg/sftpit/internal/sftpwire"
)

// maxPacketLength is pkg/sftp's own limit on the packets it reads.
const maxPacketLength = 256 * 1024

func init() {
	// pkg/sftp's advertised extensions are process-global. Links are
	// unsupported, so hardlink@openssh.com is left out.
	if err := sftp.SetSFTPExtensions(sftpwire.ExtPosixRename, sftpwire.ExtStatVFS); err != nil {
		panic(err)
	}
}

// Embedded serves SFTP sessions from the directory tree under a root. Its
// methods are safe for concurrent use.
type Embedded struct {
	root  *os.Root
	holds holds
	usage *usage
}

// Options configure an Embedded backend.
type Options struct {
	// Limits bound the files and the handles open on them.
	Limits Limits

	// Logger records each request refused at a limit. Nil means
	// slog.Default().
	Logger *slog.Logger
}

// New returns an Embedded backend that serves the files under root, which
// count towards the limits from the start. Every virtual path is resolved
// inside root and cannot escape it.
func New(root *os.Root, opts Options) (*Embedded, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	u, err := newUsage(root, opts.Limits, logger)
	if err != nil {
		return nil, err
	}
	return &Embedded{root: root, usage: u}, nil
}

// Serve serves one SFTP session on rwc until the client ends it or rwc is
// closed, resolving relative paths against home. It returns nil when the
// session ends normally.
//
// Requests are processed one at a time, in the order they arrive, as in
// OpenSSH's sftp-server. pkg/sftp alone would run reads and writes on several
// workers, so appends could land out of order and a write could race a later
// request on the same file.
func (e *Embedded) Serve(rwc io.ReadWriteCloser, home string) error {
	h := &handler{root: e.root, holds: &e.holds, usage: e.usage}
	conn, serverEnd := net.Pipe()
	srv := sftp.NewRequestServer(serverEnd,
		sftp.Handlers{FileGet: h, FilePut: h, FileCmd: h, FileList: h},
		sftp.WithStartDirectory(home),
	)
	served := make(chan error, 1)
	go func() {
		served <- srv.Serve()
		serverEnd.Close()
	}()

	err := relayInOrder(rwc, conn)
	conn.Close()
	if serveErr := <-served; errors.Is(err, errServerEnded) {
		err = serveErr
	}
	if isEndOfStream(err) {
		return nil
	}
	return err
}

var errServerEnded = errors.New("backend: request server ended the session")

// relayInOrder passes each request from client to server and waits for its
// reply before passing the next. Every request gets exactly one reply.
func relayInOrder(client, server io.ReadWriter) error {
	fromClient, fromServer := bufio.NewReader(client), bufio.NewReader(server)
	for {
		request, err := sftpwire.ReadPacket(fromClient, maxPacketLength)
		if err != nil {
			return err
		}
		if err := writePacket(server, request); err != nil {
			return errServerEnded
		}
		reply, err := sftpwire.ReadPacket(fromServer, maxPacketLength)
		if err != nil {
			return errServerEnded
		}
		if err := writePacket(client, reply); err != nil {
			return err
		}
	}
}

func writePacket(w io.Writer, body []byte) error {
	b := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(body)), uint32(len(body)))
	_, err := w.Write(append(b, body...))
	return err
}

func isEndOfStream(err error) bool {
	return err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe)
}

// Open starts a session over an in-process pipe and returns the client's end
// of it. Closing that end ends the session and waits for the backend to
// finish with it, returning any error the session ended with.
func (e *Embedded) Open(home string) io.ReadWriteCloser {
	client, server := net.Pipe()
	s := &session{Conn: client, done: make(chan error, 1)}
	go func() {
		s.done <- e.Serve(server, home)
		server.Close()
	}()
	return s
}

// MkdirAll creates the directory at the clean virtual path dir, along with
// any missing parents, unless that would take the files past a limit.
func (e *Embedded) MkdirAll(dir string) error {
	var parent string
	for _, segment := range strings.Split(strings.TrimPrefix(dir, "/"), "/") {
		parent = path.Join("/", parent, segment)
		if err := e.mkdir(parent); err != nil {
			return fmt.Errorf("backend: %w", err)
		}
	}
	return nil
}

func (e *Embedded) mkdir(dir string) error {
	defer e.usage.change(dir)()
	if info, err := e.root.Stat(rootName(dir)); err == nil && info.IsDir() {
		return nil
	}
	if limit := e.usage.limitOnCreate(dir); limit != nil {
		return limit
	}
	return e.root.Mkdir(rootName(dir), 0o755)
}

// Hold opens the file at the virtual path name for reading, outside any
// session, and holds back every change to it from every session until the
// returned file is closed. Changes already under way finish first; reads
// are never held back.
func (e *Embedded) Hold(name string) (*Held, error) {
	release := e.holds.hold(name)
	f, err := e.root.Open(rootName(name))
	if err != nil {
		release()
		return nil, fmt.Errorf("backend: hold: %w", err)
	}
	return &Held{File: f, release: release}, nil
}

// Held is a file that no session can change until it is closed.
type Held struct {
	*os.File
	release func()
	once    sync.Once
}

// Close closes the file and lets changes to it go ahead. Closing it again
// does nothing more.
func (h *Held) Close() error {
	err := h.File.Close()
	h.once.Do(h.release)
	return err
}

// StoredName returns the name, relative to the root and slash-separated,
// under which the file at the clean virtual path name is stored.
func StoredName(name string) string { return rootName(name) }

type session struct {
	net.Conn
	done chan error

	closeOnce sync.Once
	err       error
}

func (s *session) Close() error {
	s.closeOnce.Do(func() {
		s.Conn.Close()
		s.err = <-s.done
	})
	return s.err
}
