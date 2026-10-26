package sftpproxy_test

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pkg/sftp"

	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

const (
	waitTimeout = 5 * time.Second
	maxLength   = 256 * 1024
)

var openSSHVersion = sftpwire.Version{Version: 3, Extensions: []sftpwire.Extension{
	{Name: sftpwire.ExtPosixRename, Data: "1"},
	{Name: sftpwire.ExtStatVFS, Data: "2"},
	{Name: "hardlink@openssh.com", Data: "1"},
	{Name: "fsync@openssh.com", Data: "1"},
}}

// proxy is a session under test between a raw test client and a backend.
type proxy struct {
	client *rawClient
	conn   *fakeConn
	result *proxyResult
	cancel context.CancelFunc
}

// startProxy runs Serve with opts between a raw test client and backend
// until the test ends or p.cancel is called. opts.Conn and opts.Listener are
// set to a fakeConn over the client's pipe, and a nil opts.Logger discards
// the logs. The client has not sent INIT.
func startProxy(t *testing.T, backend net.Conn, opts sftpproxy.Options) *proxy {
	t.Helper()
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	clientEnd, proxyEnd := net.Pipe()
	conn := &fakeConn{stream: proxyEnd}
	opts.Conn, opts.Listener = conn, conn
	ctx, cancel := context.WithCancel(t.Context())
	result := serveInBackground(ctx, proxyEnd, backend, opts)
	t.Cleanup(func() {
		clientEnd.Close()
		result.wait(t)
	})
	return &proxy{client: newRawClient(clientEnd), conn: conn, result: result, cancel: cancel}
}

// startProxyOnFake starts a session with opts over a fake OpenSSH backend
// whose default directory is /, and sends INIT.
func startProxyOnFake(t *testing.T, opts sftpproxy.Options) (*proxy, *fakeBackend) {
	t.Helper()
	fb, backend := startFakeBackend(t, openSSHVersion, "/")
	p := startProxy(t, backend, opts)
	p.client.init(t, 3)
	return p, fb
}

// serveInBackground runs Serve on its own goroutine.
func serveInBackground(ctx context.Context, client, backend net.Conn, opts sftpproxy.Options) *proxyResult {
	result := &proxyResult{done: make(chan struct{})}
	go func() {
		defer close(result.done)
		result.err = sftpproxy.Serve(ctx, client, backend, opts)
	}()
	return result
}

type proxyResult struct {
	done chan struct{}
	err  error
}

func (r *proxyResult) wait(t *testing.T) error {
	t.Helper()
	select {
	case <-r.done:
		return r.err
	case <-time.After(waitTimeout):
		t.Fatal("timed out waiting for Serve to return")
		return nil
	}
}

// fakeConn stands in for the client's connection and the listener it came
// in through, and records what faults do to them. Closing or resetting it,
// or taking the listener down with every connection, closes the proxy's end
// of the client pipe, as closing an SSH connection ends its channels.
type fakeConn struct {
	stream net.Conn

	mu  sync.Mutex
	log []string
}

func (c *fakeConn) Close() error { c.record("close"); return c.stream.Close() }
func (c *fakeConn) Reset() error { c.record("reset"); return c.stream.Close() }
func (c *fakeConn) Freeze()      { c.record("freeze") }

func (c *fakeConn) Down(d time.Duration, closeExisting bool) {
	if !closeExisting {
		c.record(fmt.Sprintf("down %v", d))
		return
	}
	c.record(fmt.Sprintf("down %v, closing every connection", d))
	c.stream.Close()
}

func (c *fakeConn) record(event string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.log = append(c.log, event)
}

func (c *fakeConn) events() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.log)
}

// rawClient speaks SFTP packet by packet, so tests control exactly what the
// proxy receives.
type rawClient struct {
	conn net.Conn
	in   *bufio.Reader
}

func newRawClient(conn net.Conn) *rawClient {
	return &rawClient{conn: conn, in: bufio.NewReader(conn)}
}

func (c *rawClient) init(t *testing.T, version uint32) sftpwire.Version {
	t.Helper()
	c.write(t, sftpwire.AppendInit(nil, sftpwire.Init{Version: version}))
	v, err := sftpwire.DecodeVersion(c.receive(t))
	if err != nil {
		t.Fatalf("VERSION: %v", err)
	}
	return v
}

func (c *rawClient) send(t *testing.T, id uint32, p sftpwire.Packet) {
	t.Helper()
	c.write(t, sftpwire.AppendPacket(nil, id, p))
}

func (c *rawClient) sendRaw(t *testing.T, packet wire) {
	t.Helper()
	c.write(t, packet.framed())
}

// sendTogether writes requests with IDs 1, 2 and so on in a single write, as
// a pipelining client does, so the proxy has them all before it handles the
// first.
func (c *rawClient) sendTogether(t *testing.T, requests ...sftpwire.Packet) {
	t.Helper()
	var b []byte
	for i, p := range requests {
		b = sftpwire.AppendPacket(b, uint32(i+1), p)
	}
	c.write(t, b)
}

func (c *rawClient) write(t *testing.T, b []byte) {
	t.Helper()
	if err := c.conn.SetWriteDeadline(time.Now().Add(waitTimeout)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if _, err := c.conn.Write(b); err != nil {
		t.Fatalf("client write: %v", err)
	}
}

func (c *rawClient) receive(t *testing.T) []byte {
	t.Helper()
	if err := c.conn.SetReadDeadline(time.Now().Add(waitTimeout)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	b, err := sftpwire.ReadPacket(c.in, maxLength)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	return b
}

func (c *rawClient) receiveReply(t *testing.T) (uint32, sftpwire.Packet) {
	t.Helper()
	id, p, err := sftpwire.DecodeReply(c.receive(t))
	if err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	return id, p
}

func (c *rawClient) nextReplyID(t *testing.T) uint32 {
	t.Helper()
	id, _ := c.receiveReply(t)
	return id
}

// assertReplies checks that the next replies the client receives answer the
// requests with ids, in that order.
func (c *rawClient) assertReplies(t *testing.T, ids ...uint32) {
	t.Helper()
	for _, want := range ids {
		if id, p := c.receiveReply(t); id != want {
			t.Fatalf("received a reply to request %d (%v), want one to %d", id, p.Type(), want)
		}
	}
}

func (c *rawClient) assertStatus(t *testing.T, id uint32, code sftpwire.StatusCode, message string) {
	t.Helper()
	gotID, p := c.receiveReply(t)
	want := sftpwire.StatusReply{Code: code, Message: message}
	if st, ok := p.(*sftpwire.StatusReply); !ok || gotID != id || *st != want {
		t.Errorf("reply = %d %#v, want %d %#v", gotID, p, id, want)
	}
}

// assertClosed checks that the proxy closes the client's connection without
// sending anything more.
func (c *rawClient) assertClosed(t *testing.T) {
	t.Helper()
	// net.Pipe refuses deadlines once either end is closed, and reads then
	// return EOF at once.
	if err := c.conn.SetReadDeadline(time.Now().Add(waitTimeout)); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if b, err := sftpwire.ReadPacket(c.in, maxLength); !errors.Is(err, io.EOF) {
		t.Fatalf("client read = %x, %v; want the connection closed", b, err)
	}
}

// fakeBackend is a scripted SFTP server for tests that control or inspect
// exactly what the backend receives and sends.
type fakeBackend struct {
	conn     net.Conn
	requests chan backendRequest
}

type backendRequest struct {
	id     uint32
	packet sftpwire.Packet
}

// startFakeBackend returns a fake backend that answers INIT with version and
// REALPATH "." with dir, plus the proxy's end of its connection.
func startFakeBackend(t *testing.T, version sftpwire.Version, dir string) (*fakeBackend, net.Conn) {
	t.Helper()
	return startScriptedBackend(t, version, &sftpwire.NameReply{Entries: []sftpwire.NameEntry{{Filename: dir}}})
}

// startScriptedBackend is startFakeBackend with any reply to REALPATH ".".
// A nil realPath leaves REALPATH unanswered.
func startScriptedBackend(t *testing.T, version sftpwire.Version, realPath sftpwire.Packet) (*fakeBackend, net.Conn) {
	t.Helper()
	proxyEnd, backendEnd := net.Pipe()
	fb := &fakeBackend{conn: backendEnd, requests: make(chan backendRequest, 16)}
	go fb.serve(version, realPath)
	t.Cleanup(func() { backendEnd.Close() })
	return fb, proxyEnd
}

func (fb *fakeBackend) serve(version sftpwire.Version, realPath sftpwire.Packet) {
	defer close(fb.requests)
	in := bufio.NewReader(fb.conn)

	b, err := sftpwire.ReadPacket(in, maxLength)
	if err != nil {
		return
	}
	if _, err := sftpwire.DecodeInit(b); err != nil {
		return
	}
	if _, err := fb.conn.Write(sftpwire.AppendVersion(nil, version)); err != nil {
		return
	}
	for {
		b, err := sftpwire.ReadPacket(in, maxLength)
		if err != nil {
			return
		}
		id, p, err := sftpwire.DecodeRequest(b)
		if err != nil {
			return
		}
		if rp, ok := p.(*sftpwire.RealPath); ok && rp.Path == "." && realPath != nil {
			if _, err := fb.conn.Write(sftpwire.AppendPacket(nil, id, realPath)); err != nil {
				return
			}
			realPath = nil
			continue
		}
		fb.requests <- backendRequest{id: id, packet: p}
	}
}

// receive returns the next request the backend receives, or false once the
// backend connection has closed.
func (fb *fakeBackend) receive(t *testing.T) (backendRequest, bool) {
	t.Helper()
	select {
	case req, ok := <-fb.requests:
		return req, ok
	case <-time.After(waitTimeout):
		t.Fatal("timed out waiting")
		return backendRequest{}, false
	}
}

func (fb *fakeBackend) next(t *testing.T) backendRequest {
	t.Helper()
	req, ok := fb.receive(t)
	if !ok {
		t.Fatal("backend connection closed, want a request")
	}
	return req
}

func (fb *fakeBackend) reply(t *testing.T, id uint32, p sftpwire.Packet) {
	t.Helper()
	fb.write(t, sftpwire.AppendPacket(nil, id, p))
}

func (fb *fakeBackend) write(t *testing.T, b []byte) {
	t.Helper()
	if err := fb.conn.SetWriteDeadline(time.Now().Add(waitTimeout)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if _, err := fb.conn.Write(b); err != nil {
		t.Fatalf("backend write: %v", err)
	}
}

// assertNoRequest checks, once every goroutine in the synctest bubble is
// blocked, that the backend has received nothing.
func (fb *fakeBackend) assertNoRequest(t *testing.T) {
	t.Helper()
	synctest.Wait()
	select {
	case req, ok := <-fb.requests:
		if ok {
			t.Fatalf("backend received %#v, want nothing yet", req.packet)
		}
	default:
	}
}

// onPath returns faults that apply action to every request on path.
func onPath(path string, action sftpproxy.Action) func(sftpproxy.Request) sftpproxy.Action {
	return func(r sftpproxy.Request) sftpproxy.Action {
		if r.Path == path {
			return action
		}
		return nil
	}
}

// inSequence returns faults that apply actions to requests in the order
// they arrive: the first action to the first request, and so on. A nil
// action, or a request beyond the last, gets no fault.
func inSequence(actions ...sftpproxy.Action) func(sftpproxy.Request) sftpproxy.Action {
	var n int
	return func(sftpproxy.Request) sftpproxy.Action {
		n++
		if n > len(actions) {
			return nil
		}
		return actions[n-1]
	}
}

func assertPaths(t *testing.T, reqs []backendRequest, paths ...string) {
	t.Helper()
	var got []string
	for _, req := range reqs {
		stat, ok := req.packet.(*sftpwire.Stat)
		if !ok {
			t.Fatalf("backend received %#v, want a STAT", req.packet)
		}
		got = append(got, stat.Path)
	}
	if !slices.Equal(got, paths) {
		t.Errorf("backend received STATs for %v, want %v", got, paths)
	}
}

func packetTypes(packets []sftpwire.Packet) []sftpwire.PacketType {
	var types []sftpwire.PacketType
	for _, p := range packets {
		types = append(types, p.Type())
	}
	return types
}

func sameElements[T cmp.Ordered](got []T, want ...T) bool {
	return slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want)))
}

// wire builds packet bytes field by field, for packets the codec does not
// encode.
type wire []byte

func (w wire) byte(v byte) wire  { return append(w, v) }
func (w wire) u32(v uint32) wire { return binary.BigEndian.AppendUint32(w, v) }
func (w wire) str(s string) wire { return append(w.u32(uint32(len(s))), s...) }

func (w wire) framed() []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(w))), w...)
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// logger returns a logger that writes text records to b.
func (b *syncBuffer) logger() *slog.Logger { return slog.New(slog.NewTextHandler(b, nil)) }

// assertLogged checks that the logs in b contain want.
func (b *syncBuffer) assertLogged(t *testing.T, want string) {
	t.Helper()
	if logs := b.String(); !strings.Contains(logs, want) {
		t.Errorf("logs lack %s:\n%s", want, logs)
	}
}

// assertOnlyFault checks that the logs in b record one injected fault, and
// that they contain want.
func (b *syncBuffer) assertOnlyFault(t *testing.T, want string) {
	t.Helper()
	logs := b.String()
	if got := strings.Count(logs, "injected fault"); got != 1 || !strings.Contains(logs, want) {
		t.Errorf("logs have %d faults, want only %q:\n%s", got, want, logs)
	}
}

var replyOrders = []sftpproxy.ReplyOrder{sftpproxy.RequestOrder, sftpproxy.CompletionOrder}

const cutoff = 100

// answerAll answers every request the backend receives until the session
// ends: an OPEN or OPENDIR with handle "h", a READDIR with EOF, a STAT, LSTAT
// or FSTAT with a size of 10, and anything else with success.
func (fb *fakeBackend) answerAll() {
	for req := range fb.requests {
		var reply sftpwire.Packet = status(sftpwire.StatusOK)
		switch req.packet.(type) {
		case *sftpwire.Open, *sftpwire.OpenDir:
			reply = &sftpwire.HandleReply{Handle: "h"}
		case *sftpwire.ReadDir:
			reply = status(sftpwire.StatusEOF)
		case *sftpwire.Stat, *sftpwire.LStat, *sftpwire.FStat:
			reply = &sftpwire.AttrsReply{Attrs: sftpwire.Attrs{Flags: sftpwire.AttrSize, Size: 10}}
		}
		if _, err := fb.conn.Write(sftpwire.AppendPacket(nil, req.id, reply)); err != nil {
			return
		}
	}
}

// openForUpload opens /f for writing as request 1, with the backend
// answering handle.
func openForUpload(t *testing.T, p *proxy, fb *fakeBackend, handle string) {
	t.Helper()
	p.client.send(t, 1, &sftpwire.Open{Path: "/f", Flags: sftpwire.OpenWrite | sftpwire.OpenCreate | sftpwire.OpenTruncate})
	fb.reply(t, fb.next(t).id, &sftpwire.HandleReply{Handle: handle})
	p.client.assertReplies(t, 1)
}

func openForDownload(t *testing.T, p *proxy, fb *fakeBackend, handle string) {
	t.Helper()
	p.client.send(t, 1, &sftpwire.Open{Path: "/f", Flags: sftpwire.OpenRead})
	fb.reply(t, fb.next(t).id, &sftpwire.HandleReply{Handle: handle})
	p.client.assertReplies(t, 1)
}

// write returns a WRITE of length bytes at offset whose every byte is the
// low byte of its own offset, so any part of it can be told apart.
func write(handle string, offset uint64, length int) *sftpwire.Write {
	data := make([]byte, length)
	for i := range data {
		data[i] = byte(offset + uint64(i))
	}
	return &sftpwire.Write{Handle: handle, Offset: offset, Data: data}
}

func status(code sftpwire.StatusCode) *sftpwire.StatusReply {
	return &sftpwire.StatusReply{Code: code, Message: code.Message()}
}

func equalReplies(a, b sftpwire.Packet) bool {
	return bytes.Equal(sftpwire.AppendPacket(nil, 0, a), sftpwire.AppendPacket(nil, 0, b))
}

// on returns faults that apply action to every request of type P.
func on[P sftpwire.Packet](action sftpproxy.Action) func(sftpproxy.Request) sftpproxy.Action {
	return func(r sftpproxy.Request) sftpproxy.Action {
		if _, ok := r.Packet.(P); ok {
			return action
		}
		return nil
	}
}

// inMemoryBackend serves pkg/sftp's in-memory filesystem over a pipe and
// returns the client's end.
func inMemoryBackend(t *testing.T) net.Conn {
	t.Helper()
	clientEnd, serverEnd := net.Pipe()
	srv := sftp.NewRequestServer(serverEnd, sftp.InMemHandler())
	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()
	t.Cleanup(func() {
		srv.Close()
		if err := <-done; err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("backend Serve: %v", err)
		}
	})
	return clientEnd
}

// snapshotTime is how long each snapshot takes in these tests, as it might
// for a large file.
const snapshotTime = time.Second

// snapshots is a Snapshot hook that records the paths it is called with.
// Each snapshot takes snapshotTime.
type snapshots struct {
	mu    sync.Mutex
	paths []string
}

func (s *snapshots) take(path string) (sftpproxy.Snapshot, error) {
	time.Sleep(snapshotTime)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.paths = append(s.paths, path)
	return snapshotOf(path), nil
}

func (s *snapshots) taken() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.paths)
}

// snapshotLog is the log line for snapshotOf(path), closed as closedBy says,
// quoted as the log quotes it.
func snapshotLog(path, closedBy string) string {
	snap := snapshotOf(path)
	return fmt.Sprintf("level=INFO msg=snapshot path=%s closed_by=%s size=%d sha256=%x", path, closedBy, snap.Size, snap.SHA256)
}

// assertSnapshotsLogged checks that logs has exactly the snapshot lines in
// want.
func assertSnapshotsLogged(t *testing.T, logs string, want ...string) {
	t.Helper()
	var got []string
	for line := range strings.Lines(logs) {
		if strings.Contains(line, "msg=snapshot") {
			_, after, _ := strings.Cut(strings.TrimSpace(line), " ")
			got = append(got, after)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("snapshots logged:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// snapshotOf is the snapshot that snapshots gives the file at path.
func snapshotOf(path string) sftpproxy.Snapshot {
	return sftpproxy.Snapshot{Size: cutoff, SHA256: sha256.Sum256([]byte(path))}
}
