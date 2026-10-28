package sftpproxy_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
	"github.com/nebarg/sftpit/internal/testutil"
)

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
			client := startProxy(t, backend, sftpproxy.Options{}).client
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
		client := startProxy(t, backend, sftpproxy.Options{}).client
		if got := client.init(t, version); got.Version != 3 {
			t.Errorf("client version %d answered with %d, want 3", version, got.Version)
		}
	}
}

func TestRelativePathsUseBackendDirectory(t *testing.T) {
	fb, backend := startFakeBackend(t, openSSHVersion, "/home/partner-b/")
	client := startProxy(t, backend, sftpproxy.Options{}).client
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
	p, fb := startProxyOnFake(t, sftpproxy.Options{})
	client := p.client

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
	p, fb := startProxyOnFake(t, sftpproxy.Options{})
	client := p.client

	client.send(t, 1, &sftpwire.Stat{Path: "/a"})
	client.sendRaw(t, testutil.Wire{}.Byte(byte(sftpwire.TypeReadLink)).U32(2).Str("/link"))
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
		request testutil.Wire
		want    sftpwire.StatusReply
	}{
		{
			name:    "empty path",
			request: testutil.Wire{}.Byte(byte(sftpwire.TypeStat)).U32(9).Str(""),
			want:    sftpwire.StatusReply{Code: sftpwire.StatusNoSuchFile, Message: "No such file"},
		},
		{
			name:    "symlink",
			request: testutil.Wire{}.Byte(byte(sftpwire.TypeSymlink)).U32(9).Str("/a").Str("/b"),
			want:    sftpwire.StatusReply{Code: sftpwire.StatusOpUnsupported, Message: "Operation unsupported"},
		},
		{
			name:    "readlink",
			request: testutil.Wire{}.Byte(byte(sftpwire.TypeReadLink)).U32(9).Str("/a"),
			want:    sftpwire.StatusReply{Code: sftpwire.StatusOpUnsupported, Message: "Operation unsupported"},
		},
		{
			name:    "hardlink extension",
			request: testutil.Wire{}.Byte(byte(sftpwire.TypeExtended)).U32(9).Str("hardlink@openssh.com").Str("/a").Str("/b"),
			want:    sftpwire.StatusReply{Code: sftpwire.StatusOpUnsupported, Message: "Operation unsupported"},
		},
		{
			name:    "statvfs the backend lacks",
			request: testutil.Wire{}.Byte(byte(sftpwire.TypeExtended)).U32(9).Str(sftpwire.ExtStatVFS).Str("/"),
			want:    sftpwire.StatusReply{Code: sftpwire.StatusOpUnsupported, Message: "Operation unsupported"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version := sftpwire.Version{Version: 3, Extensions: []sftpwire.Extension{{Name: sftpwire.ExtPosixRename, Data: "1"}}}
			fb, backend := startFakeBackend(t, version, "/")
			client := startProxy(t, backend, sftpproxy.Options{}).client
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
	client := startProxy(t, backend, sftpproxy.Options{}).client
	first := client.init(t, 3)

	if again := client.init(t, 3); !reflect.DeepEqual(again, first) {
		t.Errorf("repeated INIT answered with %#v, want %#v", again, first)
	}
}

func TestMalformedClientInputEndsSession(t *testing.T) {
	stat := testutil.Wire{}.Byte(byte(sftpwire.TypeStat)).U32(1)

	tests := []struct {
		name      string
		skipInit  bool
		input     []byte
		thenClose bool
		wantErr   string
	}{
		{name: "request before INIT", skipInit: true, input: stat.Str("/a").Framed(), wantErr: "want SSH_FXP_INIT"},
		{name: "truncated field", input: stat.U32(10).Framed(), wantErr: "malformed"},
		{name: "NUL in a path", input: stat.Str("/a\x00").Framed(), wantErr: "malformed"},
		{name: "unknown packet type", input: testutil.Wire{}.Byte(99).U32(1).Framed(), wantErr: "not a request"},
		{name: "reply type", input: testutil.Wire{}.Byte(byte(sftpwire.TypeStatus)).U32(1).U32(0).Str("").Str("").Framed(), wantErr: "not a request"},
		{name: "packet over 256 KiB", input: testutil.Wire{}.U32(maxLength + 1), wantErr: "exceeds"},
		{name: "end inside a packet", input: stat.Framed()[:7], thenClose: true, wantErr: io.ErrUnexpectedEOF.Error()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, backend := startFakeBackend(t, openSSHVersion, "/")
			p := startProxy(t, backend, sftpproxy.Options{})
			if !tt.skipInit {
				p.client.init(t, 3)
			}
			p.client.write(t, tt.input)
			if tt.thenClose {
				p.client.conn.Close()
			} else {
				p.client.assertClosed(t)
			}

			if err := p.result.wait(t); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Serve error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestBackendViolationsEndSession(t *testing.T) {
	tests := []struct {
		name    string
		reply   func(proxyID uint32) []byte
		wantErr string
	}{
		{
			name: "reply to an unknown request",
			reply: func(proxyID uint32) []byte {
				return sftpwire.AppendPacket(nil, proxyID+100, &sftpwire.AttrsReply{})
			},
			wantErr: "unknown request",
		},
		{
			name: "reply that does not fit",
			reply: func(proxyID uint32) []byte {
				return sftpwire.AppendPacket(nil, proxyID, &sftpwire.HandleReply{Handle: "h"})
			},
			wantErr: "answered SSH_FXP_STAT with SSH_FXP_HANDLE",
		},
		{
			name: "malformed reply",
			reply: func(proxyID uint32) []byte {
				return testutil.Wire{}.Byte(byte(sftpwire.TypeStatus)).U32(proxyID).U32(0).Framed()
			},
			wantErr: "malformed",
		},
		{
			name: "request sent back as a reply",
			reply: func(proxyID uint32) []byte {
				return sftpwire.AppendPacket(nil, proxyID, &sftpwire.Stat{Path: "/a"})
			},
			wantErr: "not a reply",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, fb := startProxyOnFake(t, sftpproxy.Options{})

			p.client.send(t, 1, &sftpwire.Stat{Path: "/a"})
			fb.write(t, tt.reply(fb.next(t).id))

			p.client.assertClosed(t)
			if err := p.result.wait(t); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Serve error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// closeFails is a backend connection whose Close reports why the backend
// ended, as backend.Embedded's does.
type closeFails struct{ net.Conn }

func (c closeFails) Close() error {
	c.Conn.Close()
	return errors.New("request server failed")
}

func TestServeReportsWhyTheBackendEnded(t *testing.T) {
	fb, backend := startFakeBackend(t, openSSHVersion, "/")
	p := startProxy(t, closeFails{backend}, sftpproxy.Options{})
	p.client.init(t, 3)
	fb.conn.Close()
	p.client.assertClosed(t)
	if err := p.result.wait(t); err == nil || !strings.Contains(err.Error(), "request server failed") {
		t.Errorf("Serve = %v, want the backend's own error", err)
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
			p := startProxy(t, backend, sftpproxy.Options{})
			p.client.assertClosed(t)
			if err := p.result.wait(t); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Serve error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestBackendCloseEndsSession(t *testing.T) {
	p, fb := startProxyOnFake(t, sftpproxy.Options{})

	fb.conn.Close()
	p.client.assertClosed(t)
	if err := p.result.wait(t); err == nil || !strings.Contains(err.Error(), "backend closed the session") {
		t.Errorf("Serve error = %v, want the backend close reported", err)
	}
}

func TestClientCloseEndsSessionCleanly(t *testing.T) {
	p, fb := startProxyOnFake(t, sftpproxy.Options{})

	p.client.conn.Close()
	if err := p.result.wait(t); err != nil {
		t.Errorf("Serve after the client closed = %v, want nil", err)
	}
	if req, ok := fb.receive(t); ok {
		t.Errorf("backend received %#v, want its connection closed", req.packet)
	}
}

func TestCancelEndsSession(t *testing.T) {
	p, _ := startProxyOnFake(t, sftpproxy.Options{})

	p.cancel()
	p.client.assertClosed(t)
	if err := p.result.wait(t); !errors.Is(err, context.Canceled) {
		t.Errorf("Serve after cancel = %v, want context.Canceled", err)
	}
}

func TestDebugLogAttributesHandleRequests(t *testing.T) {
	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	fb, backend := startFakeBackend(t, openSSHVersion, "/home/partner-b")
	client := startProxy(t, backend, sftpproxy.Options{Logger: logger}).client
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
