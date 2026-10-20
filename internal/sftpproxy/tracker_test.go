package sftpproxy

import (
	"strings"
	"testing"

	"sftpit/internal/sftpwire"
)

var allExtensions = []sftpwire.Extension{
	{Name: sftpwire.ExtPosixRename, Data: "1"},
	{Name: sftpwire.ExtStatVFS, Data: "2"},
}

func TestResolve(t *testing.T) {
	tr := newTracker("/home/partner-b", nil)

	tests := []struct {
		in   string
		want string
	}{
		{in: "orders.csv", want: "/home/partner-b/orders.csv"},
		{in: ".", want: "/home/partner-b"},
		{in: "./in//orders.csv/", want: "/home/partner-b/in/orders.csv"},
		{in: "../partner-c/x", want: "/home/partner-c/x"},
		{in: "../../../..", want: "/"},
		{in: "/", want: "/"},
		{in: "/in/./a/../b", want: "/in/b"},
		{in: "//in//b", want: "/in/b"},
		{in: "/..", want: "/"},
	}
	for _, tt := range tests {
		got, ok := tr.resolve(tt.in)
		if !ok || got != tt.want {
			t.Errorf("resolve(%q) = %q, %v; want %q, true", tt.in, got, ok, tt.want)
		}
	}

	if got, ok := tr.resolve(""); ok {
		t.Errorf("resolve(\"\") = %q, true; want false", got)
	}
}

func TestTrackResolvesPathsInPlace(t *testing.T) {
	tr := newTracker("/home/p", allExtensions)

	tests := []struct {
		packet     sftpwire.Packet
		wantPath   string
		wantTarget string
	}{
		{packet: &sftpwire.Open{Path: "a"}, wantPath: "/home/p/a"},
		{packet: &sftpwire.OpenDir{Path: "in/"}, wantPath: "/home/p/in"},
		{packet: &sftpwire.Stat{Path: "a"}, wantPath: "/home/p/a"},
		{packet: &sftpwire.LStat{Path: "a"}, wantPath: "/home/p/a"},
		{packet: &sftpwire.SetStat{Path: "a"}, wantPath: "/home/p/a"},
		{packet: &sftpwire.Remove{Path: "a"}, wantPath: "/home/p/a"},
		{packet: &sftpwire.Mkdir{Path: "d"}, wantPath: "/home/p/d"},
		{packet: &sftpwire.Rmdir{Path: "d"}, wantPath: "/home/p/d"},
		{packet: &sftpwire.RealPath{Path: ""}, wantPath: "/home/p"},
		{packet: &sftpwire.RealPath{Path: "../q"}, wantPath: "/home/q"},
		{packet: &sftpwire.StatVFS{Path: "."}, wantPath: "/home/p"},
		{packet: &sftpwire.Rename{OldPath: "a.part", NewPath: "/out/a"}, wantPath: "/home/p/a.part", wantTarget: "/out/a"},
		{packet: &sftpwire.PosixRename{OldPath: "/x/../a", NewPath: "b"}, wantPath: "/a", wantTarget: "/home/p/b"},
	}
	for _, tt := range tests {
		req, rejection := tr.track(1, tt.packet, nil)
		if rejection != nil {
			t.Errorf("track(%#v) rejected with %v", tt.packet, rejection.Code)
			continue
		}
		if req.path != tt.wantPath || req.target != tt.wantTarget {
			t.Errorf("track(%T) path %q target %q, want %q and %q", tt.packet, req.path, req.target, tt.wantPath, tt.wantTarget)
		}
		forwarded := string(sftpwire.AppendPacket(nil, 0, tt.packet))
		for _, p := range []string{tt.wantPath, tt.wantTarget} {
			if !strings.Contains(forwarded, p) {
				t.Errorf("forwarded %T does not carry the resolved path %q", tt.packet, p)
			}
		}
	}
}

func TestTrackAnswersWithoutForwarding(t *testing.T) {
	tests := []struct {
		name   string
		exts   []sftpwire.Extension
		packet sftpwire.Packet
		want   sftpwire.StatusCode
	}{
		{name: "empty stat path", exts: allExtensions, packet: &sftpwire.Stat{}, want: sftpwire.StatusNoSuchFile},
		{name: "empty open path", exts: allExtensions, packet: &sftpwire.Open{Flags: sftpwire.OpenRead}, want: sftpwire.StatusNoSuchFile},
		{name: "empty rename source", exts: allExtensions, packet: &sftpwire.Rename{NewPath: "/b"}, want: sftpwire.StatusNoSuchFile},
		{name: "empty rename target", exts: allExtensions, packet: &sftpwire.Rename{OldPath: "/a"}, want: sftpwire.StatusNoSuchFile},
		{name: "empty posix-rename target", exts: allExtensions, packet: &sftpwire.PosixRename{OldPath: "/a"}, want: sftpwire.StatusNoSuchFile},
		{name: "posix-rename not offered", packet: &sftpwire.PosixRename{OldPath: "/a", NewPath: "/b"}, want: sftpwire.StatusOpUnsupported},
		{name: "statvfs not offered", packet: &sftpwire.StatVFS{Path: "/"}, want: sftpwire.StatusOpUnsupported},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := newTracker("/", tt.exts)
			_, rejection := tr.track(1, tt.packet, nil)
			if rejection == nil {
				t.Fatal("track forwarded the request")
			}
			if rejection.Code != tt.want || rejection.Message == "" {
				t.Errorf("track answered %v %q, want %v with OpenSSH's message", rejection.Code, rejection.Message, tt.want)
			}
			if len(tr.pending) != 0 {
				t.Errorf("track left %d pending requests", len(tr.pending))
			}
		})
	}
}

func TestHandleAttribution(t *testing.T) {
	tr := newTracker("/", nil)

	open, _ := tr.track(1, &sftpwire.Open{Path: "/in/orders.csv", Flags: sftpwire.OpenWrite}, nil)
	if _, err := tr.complete(open.proxyID, &sftpwire.HandleReply{Handle: "h1"}); err != nil {
		t.Fatalf("complete OPEN: %v", err)
	}
	dir, _ := tr.track(2, &sftpwire.OpenDir{Path: "/in"}, nil)
	if _, err := tr.complete(dir.proxyID, &sftpwire.HandleReply{Handle: "h2"}); err != nil {
		t.Fatalf("complete OPENDIR: %v", err)
	}

	onHandle := []struct {
		packet   sftpwire.Packet
		wantPath string
	}{
		{packet: &sftpwire.Write{Handle: "h1"}, wantPath: "/in/orders.csv"},
		{packet: &sftpwire.Read{Handle: "h1"}, wantPath: "/in/orders.csv"},
		{packet: &sftpwire.FStat{Handle: "h1"}, wantPath: "/in/orders.csv"},
		{packet: &sftpwire.FSetStat{Handle: "h1"}, wantPath: "/in/orders.csv"},
		{packet: &sftpwire.ReadDir{Handle: "h2"}, wantPath: "/in"},
		{packet: &sftpwire.Close{Handle: "h1"}, wantPath: "/in/orders.csv"},
		{packet: &sftpwire.Write{Handle: "h1"}, wantPath: ""},
		{packet: &sftpwire.Read{Handle: "unknown"}, wantPath: ""},
	}
	for _, tt := range onHandle {
		req, rejection := tr.track(3, tt.packet, nil)
		if rejection != nil {
			t.Fatalf("track(%#v) rejected with %v, want it forwarded", tt.packet, rejection.Code)
		}
		if req.path != tt.wantPath {
			t.Errorf("track(%#v) path = %q, want %q", tt.packet, req.path, tt.wantPath)
		}
	}

	reopen, _ := tr.track(4, &sftpwire.Open{Path: "/in/next.csv"}, nil)
	if _, err := tr.complete(reopen.proxyID, &sftpwire.HandleReply{Handle: "h1"}); err != nil {
		t.Fatalf("a closed handle could not be reused: %v", err)
	}
	if req, _ := tr.track(5, &sftpwire.Read{Handle: "h1"}, nil); req.path != "/in/next.csv" {
		t.Errorf("reused handle path = %q, want /in/next.csv", req.path)
	}
}

func TestCompleteRejectsReplyThatDoesNotFit(t *testing.T) {
	tests := []struct {
		name    string
		request sftpwire.Packet
		reply   sftpwire.Packet
		wantErr string
	}{
		{name: "handle for stat", request: &sftpwire.Stat{Path: "/a"}, reply: &sftpwire.HandleReply{Handle: "h"}, wantErr: "answered SSH_FXP_STAT with SSH_FXP_HANDLE"},
		{name: "attrs for open", request: &sftpwire.Open{Path: "/a"}, reply: &sftpwire.AttrsReply{}, wantErr: "answered SSH_FXP_OPEN"},
		{name: "data for readdir", request: &sftpwire.ReadDir{Handle: "h"}, reply: &sftpwire.DataReply{}, wantErr: "answered SSH_FXP_READDIR"},
		{name: "more data than requested", request: &sftpwire.Read{Handle: "h", Length: 2}, reply: &sftpwire.DataReply{Data: []byte("abc")}, wantErr: "answered SSH_FXP_READ"},
		{name: "two names for realpath", request: &sftpwire.RealPath{Path: "/"}, reply: &sftpwire.NameReply{Entries: make([]sftpwire.NameEntry, 2)}, wantErr: "answered SSH_FXP_REALPATH"},
		{name: "attrs for statvfs", request: &sftpwire.StatVFS{Path: "/"}, reply: &sftpwire.AttrsReply{}, wantErr: "answered statvfs@openssh.com"},
		{name: "extended reply for remove", request: &sftpwire.Remove{Path: "/a"}, reply: &sftpwire.ExtendedReply{}, wantErr: "answered SSH_FXP_REMOVE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := newTracker("/", allExtensions)
			req, _ := tr.track(1, tt.request, nil)
			_, err := tr.complete(req.proxyID, tt.reply)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("complete error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestCompleteAcceptsFittingReplies(t *testing.T) {
	tests := []struct {
		request sftpwire.Packet
		reply   sftpwire.Packet
	}{
		{request: &sftpwire.Open{Path: "/a"}, reply: &sftpwire.StatusReply{Code: sftpwire.StatusNoSuchFile}},
		{request: &sftpwire.Read{Handle: "h", Length: 3}, reply: &sftpwire.DataReply{Data: []byte("abc")}},
		{request: &sftpwire.Read{Handle: "h", Length: 3}, reply: &sftpwire.StatusReply{Code: sftpwire.StatusEOF}},
		{request: &sftpwire.ReadDir{Handle: "h"}, reply: &sftpwire.NameReply{Entries: make([]sftpwire.NameEntry, 3)}},
		{request: &sftpwire.RealPath{Path: "/"}, reply: &sftpwire.NameReply{Entries: make([]sftpwire.NameEntry, 1)}},
		{request: &sftpwire.LStat{Path: "/a"}, reply: &sftpwire.AttrsReply{}},
		{request: &sftpwire.StatVFS{Path: "/"}, reply: &sftpwire.ExtendedReply{}},
		{request: &sftpwire.Rename{OldPath: "/a", NewPath: "/b"}, reply: &sftpwire.StatusReply{}},
	}
	for _, tt := range tests {
		tr := newTracker("/", allExtensions)
		req, _ := tr.track(1, tt.request, nil)
		if _, err := tr.complete(req.proxyID, tt.reply); err != nil {
			t.Errorf("complete(%T after %T): %v", tt.reply, tt.request, err)
		}
	}
}

func TestCompleteRejectsUnknownRequestAndOpenHandle(t *testing.T) {
	tr := newTracker("/", nil)
	if _, err := tr.complete(99, &sftpwire.StatusReply{}); err == nil || !strings.Contains(err.Error(), "unknown request 99") {
		t.Errorf("complete for an unknown request: error = %v", err)
	}

	first, _ := tr.track(1, &sftpwire.Open{Path: "/a"}, nil)
	if _, err := tr.complete(first.proxyID, &sftpwire.HandleReply{Handle: "h"}); err != nil {
		t.Fatalf("complete first OPEN: %v", err)
	}
	second, _ := tr.track(2, &sftpwire.Open{Path: "/b"}, nil)
	if _, err := tr.complete(second.proxyID, &sftpwire.HandleReply{Handle: "h"}); err == nil || !strings.Contains(err.Error(), "already open") {
		t.Errorf("complete with a handle that is still open: error = %v", err)
	}

	if _, err := tr.complete(first.proxyID, &sftpwire.HandleReply{Handle: "h2"}); err == nil {
		t.Error("complete accepted a second reply to the same request")
	}
}

func TestProxyIDsSkipPendingRequests(t *testing.T) {
	tr := newTracker("/", nil)
	tr.nextID = 0xffffffff
	tr.pending[0] = &request{}

	var got []uint32
	for range 2 {
		req, _ := tr.track(7, &sftpwire.Stat{Path: "/a"}, nil)
		got = append(got, req.proxyID)
	}
	if got[0] != 0xffffffff || got[1] != 1 {
		t.Errorf("proxy IDs = %v, want [4294967295 1]: wrap around and skip the pending 0", got)
	}
}
