package backend_test

import (
	"path/filepath"
	"testing"

	"github.com/nebarg/sftpit/internal/sftpwire"
)

func TestRequestsThatDoNotSuitTheirHandleGetOpenSSHsAnswer(t *testing.T) {
	read := func(h string) sftpwire.Packet { return &sftpwire.Read{Handle: h, Length: 10} }
	write := func(h string) sftpwire.Packet { return &sftpwire.Write{Handle: h, Data: []byte("XX")} }
	file := func(flags uint32) sftpwire.Packet { return &sftpwire.Open{Path: "/orders.csv", Flags: flags} }
	dir := &sftpwire.OpenDir{Path: "/in"}
	tests := []struct {
		name    string
		open    sftpwire.Packet
		request func(handle string) sftpwire.Packet
		want    sftpwire.StatusCode
	}{
		// pkg/sftp's request server would serve this by writing the read
		// buffer to the file.
		{"read through a handle open only for writing", file(sftpwire.OpenWrite), read, sftpwire.StatusNoSuchFile},
		{"write through a handle open only for reading", file(sftpwire.OpenRead), write, sftpwire.StatusNoSuchFile},
		{"write through a handle that only creates", file(sftpwire.OpenCreate), write, sftpwire.StatusNoSuchFile},
		{"write through a handle that only appends", file(sftpwire.OpenAppend), write, sftpwire.StatusNoSuchFile},
		{"readdir through a file handle", file(sftpwire.OpenRead), func(h string) sftpwire.Packet { return &sftpwire.ReadDir{Handle: h} }, sftpwire.StatusFailure},
		{"read through a directory handle", dir, read, sftpwire.StatusFailure},
		{"write through a directory handle", dir, write, sftpwire.StatusFailure},
		{"fstat a directory handle", dir, func(h string) sftpwire.Packet { return &sftpwire.FStat{Handle: h} }, sftpwire.StatusFailure},
		{"fsetstat a directory handle", dir, func(h string) sftpwire.Packet {
			return &sftpwire.FSetStat{Handle: h, Attrs: sftpwire.Attrs{Flags: sftpwire.AttrPermissions, Permissions: 0o700}}
		}, sftpwire.StatusFailure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, e := newBackend(t)
			writeTree(t, dir, map[string]string{"orders.csv": "data", "in/": ""})
			s := startRaw(t, e)
			handle := s.handle(tt.open)

			reply := s.wantStatus(tt.request(handle), tt.want)
			if reply.Message != tt.want.Message() {
				t.Errorf("message = %q, want %q", reply.Message, tt.want.Message())
			}
			s.wantStatus(&sftpwire.Close{Handle: handle}, sftpwire.StatusOK)
			assertFile(t, filepath.Join(dir, "orders.csv"), "data")
		})
	}
}

func TestClosingAHandleThatIsNotOpen(t *testing.T) {
	dir, e := newBackend(t)
	writeHostFile(t, filepath.Join(dir, "orders.csv"), "data")
	s := startRaw(t, e)
	s.wantStatus(&sftpwire.Close{Handle: "unknown"}, sftpwire.StatusNoSuchFile)

	handle := s.handle(&sftpwire.Open{Path: "/orders.csv", Flags: sftpwire.OpenRead})
	s.wantStatus(&sftpwire.Close{Handle: handle}, sftpwire.StatusOK)
	s.wantStatus(&sftpwire.Close{Handle: handle}, sftpwire.StatusNoSuchFile)
	// Other requests on a closed handle fail as they do in OpenSSH.
	s.wantStatus(&sftpwire.Read{Handle: handle, Length: 10}, sftpwire.StatusFailure)
}

func TestOpensThatAskNeitherToReadNorToWriteCanRead(t *testing.T) {
	dir, e := newBackend(t)
	writeHostFile(t, filepath.Join(dir, "orders.csv"), "data")
	s := startRaw(t, e)
	for _, open := range []*sftpwire.Open{
		{Path: "/orders.csv"},
		{Path: "/orders.csv", Flags: sftpwire.OpenCreate},
		{Path: "/orders.csv", Flags: sftpwire.OpenAppend},
	} {
		handle := s.handle(open)
		if data, ok := s.send(&sftpwire.Read{Handle: handle, Length: 10}).(*sftpwire.DataReply); !ok || string(data.Data) != "data" {
			t.Errorf("read after an OPEN with flags %#x = %#v, want the file", open.Flags, data)
		}
		s.wantStatus(&sftpwire.Close{Handle: handle}, sftpwire.StatusOK)
	}
	handle := s.handle(&sftpwire.Open{Path: "/new.csv", Flags: sftpwire.OpenCreate})
	s.wantStatus(&sftpwire.Read{Handle: handle, Length: 10}, sftpwire.StatusEOF)
	assertFile(t, filepath.Join(dir, "new.csv"), "")
}

func TestEveryStatusCarriesOpenSSHsMessage(t *testing.T) {
	dir, e := newBackend(t)
	writeHostFile(t, filepath.Join(dir, "orders.csv"), "data")
	s := startRaw(t, e)
	handle := s.handle(&sftpwire.Open{Path: "/orders.csv", Flags: sftpwire.OpenRead})
	for _, tt := range []struct {
		request sftpwire.Packet
		want    sftpwire.StatusCode
	}{
		{&sftpwire.Read{Handle: handle, Offset: 4, Length: 10}, sftpwire.StatusEOF},
		{&sftpwire.Close{Handle: handle}, sftpwire.StatusOK},
		// pkg/sftp's own message for an unknown handle is "bad file
		// descriptor".
		{&sftpwire.FStat{Handle: handle}, sftpwire.StatusFailure},
	} {
		if reply := s.wantStatus(tt.request, tt.want); reply.Message != tt.want.Message() || reply.Language != "" {
			t.Errorf("%v: message %q in %q, want %q with no language tag", tt.request.Type(), reply.Message, reply.Language, tt.want.Message())
		}
	}
}
