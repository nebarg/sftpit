package sftpproxy_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"sftpit/internal/sftpproxy"
	"sftpit/internal/sftpwire"
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

func TestExtensionsOffered(t *testing.T) {
	tests := []struct {
		name    string
		backend []sftpwire.Extension
		want    []sftpwire.Extension
	}{
		{
			name:    "OpenSSH set",
			backend: openSSHVersion.Extensions,
			want:    openSSHVersion.Extensions[:2],
		},
		{
			name:    "different statvfs version",
			backend: []sftpwire.Extension{{Name: sftpwire.ExtStatVFS, Data: "1"}, {Name: sftpwire.ExtPosixRename, Data: "1"}},
			want:    []sftpwire.Extension{{Name: sftpwire.ExtPosixRename, Data: "1"}},
		},
		{
			name: "none",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, backend := startFakeBackend(t, sftpwire.Version{Version: 3, Extensions: tt.backend}, "/")
			client, _ := startProxy(t, context.Background(), backend)
			got := client.init(t, 3)
			if got.Version != 3 || !reflect.DeepEqual(got.Extensions, tt.want) {
				t.Errorf("VERSION = %d %v, want 3 %v", got.Version, got.Extensions, tt.want)
			}
		})
	}
}

func TestClientVersionIsAnsweredWithVersion3(t *testing.T) {
	for _, version := range []uint32{2, 3, 6} {
		_, backend := startFakeBackend(t, openSSHVersion, "/")
		client, _ := startProxy(t, context.Background(), backend)
		if got := client.init(t, version); got.Version != 3 {
			t.Errorf("client version %d answered with %d, want 3", version, got.Version)
		}
	}
}

func TestRelativePathsUseBackendDirectory(t *testing.T) {
	fb, backend := startFakeBackend(t, openSSHVersion, "/home/partner-b/")
	client, _ := startProxy(t, context.Background(), backend)
	client.init(t, 3)

	tests := []struct {
		sent sftpwire.Packet
		want sftpwire.Packet
	}{
		{sent: &sftpwire.Stat{Path: "orders.csv"}, want: &sftpwire.Stat{Path: "/home/partner-b/orders.csv"}},
		{sent: &sftpwire.RealPath{Path: ""}, want: &sftpwire.RealPath{Path: "/home/partner-b"}},
		{sent: &sftpwire.Rename{OldPath: "in/a.part", NewPath: "../shared/a.csv"}, want: &sftpwire.Rename{OldPath: "/home/partner-b/in/a.part", NewPath: "/home/shared/a.csv"}},
		{sent: &sftpwire.Open{Path: "/out//./b.csv", Flags: sftpwire.OpenRead}, want: &sftpwire.Open{Path: "/out/b.csv", Flags: sftpwire.OpenRead}},
	}
	for _, tt := range tests {
		client.send(t, 1, tt.sent)
		if got := fb.next(t); !reflect.DeepEqual(got.packet, tt.want) {
			t.Errorf("backend received %#v, want %#v", got.packet, tt.want)
		}
	}
}

func TestRequestIDsAreRemapped(t *testing.T) {
	fb, backend := startFakeBackend(t, openSSHVersion, "/")
	client, _ := startProxy(t, context.Background(), backend)
	client.init(t, 3)

	clientIDs := []uint32{7, 7, 0, 0xffffffff}
	for _, id := range clientIDs {
		client.send(t, id, &sftpwire.Stat{Path: "/a"})
	}
	seen := make(map[uint32]bool)
	for range clientIDs {
		req := fb.next(t)
		if seen[req.id] {
			t.Errorf("backend received proxy ID %d twice", req.id)
		}
		seen[req.id] = true
		fb.reply(t, req.id, &sftpwire.AttrsReply{})
	}
	for _, want := range clientIDs {
		if id, _ := client.receiveReply(t); id != want {
			t.Errorf("reply ID = %d, want %d", id, want)
		}
	}
}

func TestRepliesFollowRequestOrder(t *testing.T) {
	fb, backend := startFakeBackend(t, openSSHVersion, "/")
	client, _ := startProxy(t, context.Background(), backend)
	client.init(t, 3)

	client.send(t, 1, &sftpwire.Stat{Path: "/a"})
	client.sendRaw(t, wire{}.byte(byte(sftpwire.TypeReadLink)).u32(2).str("/link"))
	client.send(t, 3, &sftpwire.Stat{Path: "/b"})
	a, b := fb.next(t), fb.next(t)

	fb.reply(t, b.id, &sftpwire.StatusReply{Code: sftpwire.StatusNoSuchFile})
	fb.reply(t, a.id, &sftpwire.AttrsReply{})

	want := []struct {
		id   uint32
		kind sftpwire.PacketType
	}{{1, sftpwire.TypeAttrs}, {2, sftpwire.TypeStatus}, {3, sftpwire.TypeStatus}}
	for _, w := range want {
		id, p := client.receiveReply(t)
		if id != w.id || p.Type() != w.kind {
			t.Errorf("reply = %d %v, want %d %v", id, p.Type(), w.id, w.kind)
		}
	}
}

func TestProxyAnswersWithoutTheBackend(t *testing.T) {
	tests := []struct {
		name    string
		request wire
		want    sftpwire.StatusReply
	}{
		{
			name:    "empty path",
			request: wire{}.byte(byte(sftpwire.TypeStat)).u32(9).str(""),
			want:    sftpwire.StatusReply{Code: sftpwire.StatusNoSuchFile, Message: "No such file"},
		},
		{
			name:    "symlink",
			request: wire{}.byte(byte(sftpwire.TypeSymlink)).u32(9).str("/a").str("/b"),
			want:    sftpwire.StatusReply{Code: sftpwire.StatusOpUnsupported, Message: "Operation unsupported"},
		},
		{
			name:    "readlink",
			request: wire{}.byte(byte(sftpwire.TypeReadLink)).u32(9).str("/a"),
			want:    sftpwire.StatusReply{Code: sftpwire.StatusOpUnsupported, Message: "Operation unsupported"},
		},
		{
			name:    "hardlink extension",
			request: wire{}.byte(byte(sftpwire.TypeExtended)).u32(9).str("hardlink@openssh.com").str("/a").str("/b"),
			want:    sftpwire.StatusReply{Code: sftpwire.StatusOpUnsupported, Message: "Operation unsupported"},
		},
		{
			name:    "statvfs the backend lacks",
			request: wire{}.byte(byte(sftpwire.TypeExtended)).u32(9).str(sftpwire.ExtStatVFS).str("/"),
			want:    sftpwire.StatusReply{Code: sftpwire.StatusOpUnsupported, Message: "Operation unsupported"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version := sftpwire.Version{Version: 3, Extensions: []sftpwire.Extension{{Name: sftpwire.ExtPosixRename, Data: "1"}}}
			fb, backend := startFakeBackend(t, version, "/")
			client, _ := startProxy(t, context.Background(), backend)
			client.init(t, 3)

			client.sendRaw(t, tt.request)
			client.send(t, 10, &sftpwire.Stat{Path: "/after"})

			if got := fb.next(t); !reflect.DeepEqual(got.packet, &sftpwire.Stat{Path: "/after"}) {
				t.Errorf("backend received %#v first, want only the request that followed", got.packet)
			}
			id, p := client.receiveReply(t)
			if st, ok := p.(*sftpwire.StatusReply); !ok || id != 9 || *st != tt.want {
				t.Errorf("reply = %d %#v, want 9 %#v", id, p, tt.want)
			}
		})
	}
}

func TestRepeatedInitIsAnsweredAgain(t *testing.T) {
	_, backend := startFakeBackend(t, openSSHVersion, "/")
	client, _ := startProxy(t, context.Background(), backend)
	first := client.init(t, 3)

	client.sendRaw(t, wire(sftpwire.AppendInit(nil, sftpwire.Init{Version: 3})[4:]))
	again, err := sftpwire.DecodeVersion(client.receive(t))
	if err != nil {
		t.Fatalf("reply to a repeated INIT: %v", err)
	}
	if !reflect.DeepEqual(again, first) {
		t.Errorf("repeated INIT answered with %#v, want %#v", again, first)
	}
}

func TestMalformedClientInputEndsSession(t *testing.T) {
	stat := wire{}.byte(byte(sftpwire.TypeStat)).u32(1)

	tests := []struct {
		name      string
		skipInit  bool
		input     []byte
		thenClose bool
		wantErr   string
	}{
		{name: "request before INIT", skipInit: true, input: stat.str("/a").framed(), wantErr: "want SSH_FXP_INIT"},
		{name: "truncated field", input: stat.u32(10).framed(), wantErr: "malformed"},
		{name: "NUL in a path", input: stat.str("/a\x00").framed(), wantErr: "malformed"},
		{name: "unknown packet type", input: wire{}.byte(99).u32(1).framed(), wantErr: "not a request"},
		{name: "reply type", input: wire{}.byte(byte(sftpwire.TypeStatus)).u32(1).u32(0).str("").str("").framed(), wantErr: "not a request"},
		{name: "packet over 256 KiB", input: wire{}.u32(maxLength + 1), wantErr: "exceeds"},
		{name: "end inside a packet", input: stat.framed()[:7], thenClose: true, wantErr: io.ErrUnexpectedEOF.Error()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, backend := startFakeBackend(t, openSSHVersion, "/")
			client, result := startProxy(t, context.Background(), backend)
			if !tt.skipInit {
				client.init(t, 3)
			}
			client.write(t, tt.input)
			if tt.thenClose {
				client.conn.Close()
			} else {
				client.assertClosed(t)
			}

			if err := result.wait(t); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Serve error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestBackendViolationsEndSession(t *testing.T) {
	tests := []struct {
		name    string
		request sftpwire.Packet
		reply   func(proxyID uint32) []byte
		wantErr string
	}{
		{
			name:    "reply to an unknown request",
			request: &sftpwire.Stat{Path: "/a"},
			reply: func(proxyID uint32) []byte {
				return sftpwire.AppendPacket(nil, proxyID+100, &sftpwire.AttrsReply{})
			},
			wantErr: "unknown request",
		},
		{
			name:    "reply that does not fit",
			request: &sftpwire.Stat{Path: "/a"},
			reply: func(proxyID uint32) []byte {
				return sftpwire.AppendPacket(nil, proxyID, &sftpwire.HandleReply{Handle: "h"})
			},
			wantErr: "answered SSH_FXP_STAT with SSH_FXP_HANDLE",
		},
		{
			name:    "malformed reply",
			request: &sftpwire.Stat{Path: "/a"},
			reply: func(proxyID uint32) []byte {
				return wire{}.byte(byte(sftpwire.TypeStatus)).u32(proxyID).u32(0).framed()
			},
			wantErr: "malformed",
		},
		{
			name:    "request sent back as a reply",
			request: &sftpwire.Stat{Path: "/a"},
			reply: func(proxyID uint32) []byte {
				return sftpwire.AppendPacket(nil, proxyID, &sftpwire.Stat{Path: "/a"})
			},
			wantErr: "not a reply",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fb, backend := startFakeBackend(t, openSSHVersion, "/")
			client, result := startProxy(t, context.Background(), backend)
			client.init(t, 3)

			client.send(t, 1, tt.request)
			fb.write(t, tt.reply(fb.next(t).id))

			client.assertClosed(t)
			if err := result.wait(t); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Serve error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestBackendStartupFailuresEndSession(t *testing.T) {
	tests := []struct {
		name     string
		version  sftpwire.Version
		realPath sftpwire.Packet
		wantErr  string
	}{
		{
			name:    "other protocol version",
			version: sftpwire.Version{Version: 4},
			wantErr: "backend speaks SFTP version 4",
		},
		{
			name:     "REALPATH fails",
			version:  openSSHVersion,
			realPath: &sftpwire.StatusReply{Code: sftpwire.StatusPermissionDenied, Message: "Permission denied"},
			wantErr:  "SSH_FX_PERMISSION_DENIED",
		},
		{
			name:     "REALPATH gives a relative path",
			version:  openSSHVersion,
			realPath: &sftpwire.NameReply{Entries: []sftpwire.NameEntry{{Filename: "home"}}},
			wantErr:  "no absolute path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, backend := startScriptedBackend(t, tt.version, tt.realPath)
			client, result := startProxy(t, context.Background(), backend)
			client.assertClosed(t)
			if err := result.wait(t); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Serve error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestBackendCloseEndsSession(t *testing.T) {
	fb, backend := startFakeBackend(t, openSSHVersion, "/")
	client, result := startProxy(t, context.Background(), backend)
	client.init(t, 3)

	fb.conn.Close()
	client.assertClosed(t)
	if err := result.wait(t); err == nil || !strings.Contains(err.Error(), "backend closed the session") {
		t.Errorf("Serve error = %v, want the backend close reported", err)
	}
}

func TestClientCloseEndsSessionCleanly(t *testing.T) {
	fb, backend := startFakeBackend(t, openSSHVersion, "/")
	client, result := startProxy(t, context.Background(), backend)
	client.init(t, 3)

	client.conn.Close()
	if err := result.wait(t); err != nil {
		t.Errorf("Serve after the client closed = %v, want nil", err)
	}
	if req, ok := receive(t, fb.requests); ok {
		t.Errorf("backend received %#v, want its connection closed", req.packet)
	}
}

func TestCancelEndsSession(t *testing.T) {
	_, backend := startFakeBackend(t, openSSHVersion, "/")
	ctx, cancel := context.WithCancel(context.Background())
	client, result := startProxy(t, ctx, backend)
	client.init(t, 3)

	cancel()
	client.assertClosed(t)
	if err := result.wait(t); !errors.Is(err, context.Canceled) {
		t.Errorf("Serve after cancel = %v, want context.Canceled", err)
	}
}

func TestDebugLogAttributesHandleRequests(t *testing.T) {
	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	fb, backend := startFakeBackend(t, openSSHVersion, "/home/partner-b")
	client, _ := startProxyWith(t, context.Background(), backend, sftpproxy.Options{Logger: logger})
	client.init(t, 3)

	client.send(t, 1, &sftpwire.Open{Path: "orders.csv", Flags: sftpwire.OpenWrite | sftpwire.OpenCreate})
	fb.reply(t, fb.next(t).id, &sftpwire.HandleReply{Handle: "h"})
	client.receiveReply(t)
	client.send(t, 2, &sftpwire.Write{Handle: "h", Data: []byte("x")})
	fb.reply(t, fb.next(t).id, &sftpwire.StatusReply{})
	client.receiveReply(t)

	logged := logs.String()
	for _, want := range []string{
		"request=SSH_FXP_OPEN path=/home/partner-b/orders.csv result=SSH_FXP_HANDLE",
		"request=SSH_FXP_WRITE path=/home/partner-b/orders.csv result=SSH_FX_OK",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("log does not contain %q:\n%s", want, logged)
		}
	}
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

func startProxy(t *testing.T, ctx context.Context, backend net.Conn) (*rawClient, *proxyResult) {
	t.Helper()
	return startProxyWith(t, ctx, backend, sftpproxy.Options{Logger: slog.New(slog.DiscardHandler)})
}

// startProxyWith runs Serve with opts between a pipe to a raw test client
// and backend.
func startProxyWith(t *testing.T, ctx context.Context, backend net.Conn, opts sftpproxy.Options) (*rawClient, *proxyResult) {
	t.Helper()
	clientEnd, proxyEnd := net.Pipe()
	result := &proxyResult{done: make(chan struct{})}
	go func() {
		defer close(result.done)
		result.err = sftpproxy.Serve(ctx, proxyEnd, backend, opts)
	}()
	t.Cleanup(func() {
		clientEnd.Close()
		result.wait(t)
	})
	return &rawClient{conn: clientEnd, in: bufio.NewReader(clientEnd)}, result
}

// rawClient speaks SFTP packet by packet, so tests control exactly what the
// proxy receives.
type rawClient struct {
	conn net.Conn
	in   *bufio.Reader
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

func (fb *fakeBackend) next(t *testing.T) backendRequest {
	t.Helper()
	req, ok := receive(t, fb.requests)
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

func receive[T any](t *testing.T, ch <-chan T) (T, bool) {
	t.Helper()
	select {
	case v, ok := <-ch:
		return v, ok
	case <-time.After(waitTimeout):
		t.Fatal("timed out waiting")
		var zero T
		return zero, false
	}
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
