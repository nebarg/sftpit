package backend_test

import (
	"os"
	"path"
	"path/filepath"
	"syscall"
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
		// pkg/sftp's request server would truncate the file by its path.
		{"fsetstat the size through a handle open only for reading", file(sftpwire.OpenRead), func(h string) sftpwire.Packet {
			return &sftpwire.FSetStat{Handle: h, Attrs: sftpwire.Attrs{Flags: sftpwire.AttrSize, Size: 2}}
		}, sftpwire.StatusBadMessage},
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
		{&sftpwire.Stat{Path: "/missing/orders.csv"}, sftpwire.StatusNoSuchFile},
		// A file used as a directory.
		{&sftpwire.Stat{Path: "/orders.csv/inner"}, sftpwire.StatusNoSuchFile},
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

func TestListingsStartWithDotAndDotDot(t *testing.T) {
	dir, e := newBackend(t)
	writeTree(t, dir, map[string]string{"in/orders.csv": "data"})
	if err := os.Chmod(filepath.Join(dir, "in"), 0o750); err != nil {
		t.Fatal(err)
	}
	s := startRaw(t, e)
	permissions := func(name string) uint32 {
		attrs, ok := s.send(&sftpwire.Stat{Path: name}).(*sftpwire.AttrsReply)
		if !ok {
			t.Fatalf("STAT %s failed", name)
		}
		return attrs.Attrs.Permissions
	}
	// The root is its own parent, as in a chroot.
	for _, tt := range []struct{ dir, parent, entry string }{
		{"/in", "/", "orders.csv"},
		{"/", "/", "in"},
	} {
		handle := s.handle(&sftpwire.OpenDir{Path: tt.dir})
		names, ok := s.send(&sftpwire.ReadDir{Handle: handle}).(*sftpwire.NameReply)
		if !ok || len(names.Entries) != 3 {
			t.Fatalf("READDIR %s = %#v, want three entries", tt.dir, names)
		}
		for i, want := range []struct {
			name        string
			permissions uint32
		}{{".", permissions(tt.dir)}, {"..", permissions(tt.parent)}, {tt.entry, permissions(path.Join(tt.dir, tt.entry))}} {
			if got := names.Entries[i]; got.Filename != want.name || got.Attrs.Permissions != want.permissions {
				t.Errorf("READDIR %s entry %d = %q with permissions %#o, want %q with %#o", tt.dir, i, got.Filename, got.Attrs.Permissions, want.name, want.permissions)
			}
		}
		s.wantStatus(&sftpwire.Close{Handle: handle}, sftpwire.StatusOK)
	}
}

// TestCreatesGetThePermissionsTheyAskFor clears the umask, so that each mode
// is exactly what the backend asked the host for, whatever the umask of the
// machine running the tests.
func TestCreatesGetThePermissionsTheyAskFor(t *testing.T) {
	umask := syscall.Umask(0)
	t.Cleanup(func() { syscall.Umask(umask) })
	dir, e := newBackend(t)
	writeHostFile(t, filepath.Join(dir, "existing.csv"), "data")
	existing := hostMode(t, filepath.Join(dir, "existing.csv"))

	s := startRaw(t, e)
	create := func(name string, attrs sftpwire.Attrs) {
		handle := s.handle(&sftpwire.Open{Path: name, Flags: sftpwire.OpenWrite | sftpwire.OpenCreate, Attrs: attrs})
		s.wantStatus(&sftpwire.Close{Handle: handle}, sftpwire.StatusOK)
	}
	create("/private.csv", withPermissions(0o600))
	create("/setuid.sh", withPermissions(0o4755))
	s.wantStatus(&sftpwire.Mkdir{Path: "/private", Attrs: withPermissions(0o700)}, sftpwire.StatusOK)
	s.wantStatus(&sftpwire.Mkdir{Path: "/setuid", Attrs: withPermissions(0o4755)}, sftpwire.StatusOK)
	// A request that asks for no permissions gets the default, whatever the
	// one before it asked for.
	create("/default.csv", sftpwire.Attrs{})
	s.wantStatus(&sftpwire.Mkdir{Path: "/default"}, sftpwire.StatusOK)
	create("/existing.csv", withPermissions(0o600))

	for name, want := range map[string]os.FileMode{
		"private.csv":  0o600,
		"setuid.sh":    0o755,
		"private":      0o700,
		"setuid":       0o755,
		"default.csv":  0o666,
		"default":      0o777,
		"existing.csv": existing,
	} {
		if got := hostMode(t, filepath.Join(dir, name)); got != want {
			t.Errorf("%s has mode %v, want %v", name, got, want)
		}
	}
}

func withPermissions(mode uint32) sftpwire.Attrs {
	return sftpwire.Attrs{Flags: sftpwire.AttrPermissions, Permissions: mode}
}

// hostMode returns the permissions and special bits of the file name.
func hostMode(t *testing.T, name string) os.FileMode {
	t.Helper()
	info, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode() &^ os.ModeType
}
