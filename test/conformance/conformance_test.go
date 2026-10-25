package conformance

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/sftpwire"
)

// step is one request of a script. A request that uses a handle names the
// step that opened it.
type step struct {
	name    string
	request func(handles map[string]string) sftpwire.Packet
}

func req(p sftpwire.Packet) func(map[string]string) sftpwire.Packet {
	return func(map[string]string) sftpwire.Packet { return p }
}

func open(name string, flags uint32) func(map[string]string) sftpwire.Packet {
	return req(&sftpwire.Open{Path: name, Flags: flags})
}

func write(handle string, off uint64, data string) func(map[string]string) sftpwire.Packet {
	return func(h map[string]string) sftpwire.Packet {
		return &sftpwire.Write{Handle: h[handle], Offset: off, Data: []byte(data)}
	}
}

func read(handle string, off uint64, n uint32) func(map[string]string) sftpwire.Packet {
	return func(h map[string]string) sftpwire.Packet {
		return &sftpwire.Read{Handle: h[handle], Offset: off, Length: n}
	}
}

func closeHandle(handle string) func(map[string]string) sftpwire.Packet {
	return func(h map[string]string) sftpwire.Packet { return &sftpwire.Close{Handle: h[handle]} }
}

func fstat(handle string) func(map[string]string) sftpwire.Packet {
	return func(h map[string]string) sftpwire.Packet { return &sftpwire.FStat{Handle: h[handle]} }
}

func fsetstat(handle string, attrs sftpwire.Attrs) func(map[string]string) sftpwire.Packet {
	return func(h map[string]string) sftpwire.Packet { return &sftpwire.FSetStat{Handle: h[handle], Attrs: attrs} }
}

func readdir(handle string) func(map[string]string) sftpwire.Packet {
	return func(h map[string]string) sftpwire.Packet { return &sftpwire.ReadDir{Handle: h[handle]} }
}

func perms(mode uint32) sftpwire.Attrs {
	return sftpwire.Attrs{Flags: sftpwire.AttrPermissions, Permissions: mode}
}

func size(n uint64) sftpwire.Attrs {
	return sftpwire.Attrs{Flags: sftpwire.AttrSize, Size: n}
}

var stamped = sftpwire.Attrs{Flags: sftpwire.AttrACModTime, ATime: uint32(stamp.Unix()), MTime: uint32(stamp.Unix())}

const (
	rd     = sftpwire.OpenRead
	wr     = sftpwire.OpenWrite
	create = sftpwire.OpenWrite | sftpwire.OpenCreate | sftpwire.OpenTruncate
)

// file returns the steps that create name holding content.
func file(name, content string) []step {
	return []step{
		{"create " + name, open(name, create)},
		{"write " + name, write("create "+name, 0, content)},
		{"close " + name, closeHandle("create " + name)},
	}
}

var scripts = map[string][]step{
	"transfers": {
		{"create", open("a.txt", create)},
		{"write", write("create", 0, "hello")},
		{"write after", write("create", 5, " world")},
		{"fstat", fstat("create")},
		{"close", closeHandle("create")},
		{"open for reading", open("a.txt", rd)},
		{"read", read("open for reading", 0, 100)},
		{"read from the middle", read("open for reading", 6, 3)},
		{"read at the end", read("open for reading", 11, 100)},
		{"read past the end", read("open for reading", 1000, 10)},
		{"close after reading", closeHandle("open for reading")},
		{"read a closed handle", read("open for reading", 0, 10)},
		{"close a closed handle", closeHandle("open for reading")},
		{"close an unknown handle", req(&sftpwire.Close{Handle: "unknown"})},
		{"stat", req(&sftpwire.Stat{Path: "a.txt"})},
		{"lstat", req(&sftpwire.LStat{Path: "a.txt"})},
		{"stat a missing file", req(&sftpwire.Stat{Path: "missing"})},
		{"lstat a missing file", req(&sftpwire.LStat{Path: "missing"})},
		{"create a sparse file", open("sparse.bin", create)},
		{"write past the end", write("create a sparse file", 100, "x")},
		{"close the sparse file", closeHandle("create a sparse file")},
		{"stat the sparse file", req(&sftpwire.Stat{Path: "sparse.bin"})},
		{"create an empty file", open("empty.txt", create)},
		{"close the empty file", closeHandle("create an empty file")},
		{"open the empty file", open("empty.txt", rd)},
		{"read the empty file", read("open the empty file", 0, 10)},
		{"close the empty file again", closeHandle("open the empty file")},
	},
	"open flags": concat(
		file("a.txt", "0123456789"),
		[]step{
			{"exclusive create", open("x.txt", create|sftpwire.OpenExclusive)},
			{"close the exclusive file", closeHandle("exclusive create")},
			{"exclusive create of an existing file", open("x.txt", create|sftpwire.OpenExclusive)},
			{"read a missing file", open("missing", rd)},
			{"write a missing file without create", open("missing", wr)},
			{"create in a missing directory", open("missing/a.txt", create)},
			{"truncate", open("a.txt", wr|sftpwire.OpenTruncate)},
			{"close the truncated file", closeHandle("truncate")},
			{"stat the truncated file", req(&sftpwire.Stat{Path: "a.txt"})},
			{"append", open("log.txt", wr|sftpwire.OpenCreate|sftpwire.OpenAppend)},
			{"append one", write("append", 0, "one ")},
			{"append two", write("append", 0, "two")},
			{"close the appended file", closeHandle("append")},
			{"read and write", open("rw.txt", rd|wr|sftpwire.OpenCreate)},
			{"write through a read-write handle", write("read and write", 0, "abc")},
			{"read through a read-write handle", read("read and write", 0, 10)},
			{"close the read-write handle", closeHandle("read and write")},
			{"read only", open("rw.txt", rd)},
			{"write through a read-only handle", write("read only", 0, "x")},
			{"close the read-only handle", closeHandle("read only")},
			{"write only", open("rw.txt", wr)},
			{"read through a write-only handle", read("write only", 0, 10)},
			{"close the write-only handle", closeHandle("write only")},
			{"create without read or write", open("c.txt", sftpwire.OpenCreate)},
			{"read through a handle that only creates", read("create without read or write", 0, 10)},
			{"write through a handle that only creates", write("create without read or write", 0, "x")},
			{"close the created file", closeHandle("create without read or write")},
			{"stat the created file", req(&sftpwire.Stat{Path: "c.txt"})},
			{"open with no flags", open("a.txt", 0)},
			{"read through a handle with no flags", read("open with no flags", 0, 10)},
			{"close the handle with no flags", closeHandle("open with no flags")},
			{"mkdir", req(&sftpwire.Mkdir{Path: "d"})},
			{"open a directory for reading", open("d", rd)},
			{"read a directory", read("open a directory for reading", 0, 10)},
			{"close the directory", closeHandle("open a directory for reading")},
			{"open a directory for writing", open("d", wr)},
			{"opendir", req(&sftpwire.OpenDir{Path: "d"})},
			{"read through a directory handle", read("opendir", 0, 10)},
			{"write through a directory handle", write("opendir", 0, "x")},
			{"fstat a directory handle", fstat("opendir")},
			{"fsetstat a directory handle", fsetstat("opendir", perms(0o755))},
			{"close the directory handle", closeHandle("opendir")},
			{"open a file to list", open("a.txt", rd)},
			{"readdir a file handle", readdir("open a file to list")},
			{"close the file handle", closeHandle("open a file to list")},
			{"readdir a closed handle", readdir("open a file to list")},
			{"fstat a closed handle", fstat("open a file to list")},
			{"create with permissions", req(&sftpwire.Open{Path: "p.txt", Flags: create, Attrs: perms(0o600)})},
			{"close the file created with permissions", closeHandle("create with permissions")},
			{"stat the file created with permissions", req(&sftpwire.Stat{Path: "p.txt"})},
			{"open an existing file with permissions", req(&sftpwire.Open{Path: "a.txt", Flags: wr, Attrs: perms(0o600)})},
			{"close the existing file", closeHandle("open an existing file with permissions")},
			{"stat the existing file", req(&sftpwire.Stat{Path: "a.txt"})},
			{"create with setuid", req(&sftpwire.Open{Path: "s.sh", Flags: create, Attrs: perms(0o4755)})},
			{"close the file created with setuid", closeHandle("create with setuid")},
			{"stat the file created with setuid", req(&sftpwire.Stat{Path: "s.sh"})},
		},
	),
	"setstat": concat(
		file("a.txt", "0123456789"),
		[]step{
			{"mkdir", req(&sftpwire.Mkdir{Path: "d"})},
			{"shrink", req(&sftpwire.SetStat{Path: "a.txt", Attrs: size(4)})},
			{"stat after shrinking", req(&sftpwire.Stat{Path: "a.txt"})},
			{"grow", req(&sftpwire.SetStat{Path: "a.txt", Attrs: size(8)})},
			{"open the grown file", open("a.txt", rd)},
			{"read the grown file", read("open the grown file", 0, 100)},
			{"close the grown file", closeHandle("open the grown file")},
			{"chmod", req(&sftpwire.SetStat{Path: "a.txt", Attrs: perms(0o640)})},
			{"stat after chmod", req(&sftpwire.Stat{Path: "a.txt"})},
			{"chmod with setuid", req(&sftpwire.SetStat{Path: "a.txt", Attrs: perms(0o4755)})},
			{"stat after chmod with setuid", req(&sftpwire.Stat{Path: "a.txt"})},
			{"chmod back", req(&sftpwire.SetStat{Path: "a.txt", Attrs: perms(0o644)})},
			{"set times", req(&sftpwire.SetStat{Path: "a.txt", Attrs: stamped})},
			{"stat after setting times", req(&sftpwire.Stat{Path: "a.txt"})},
			{"chown to the owner", req(&sftpwire.SetStat{Path: "a.txt", Attrs: sftpwire.Attrs{
				Flags: sftpwire.AttrUIDGID, UID: uint32(os.Getuid()), GID: uint32(os.Getgid()),
			}})},
			{"chown to another user", req(&sftpwire.SetStat{Path: "a.txt", Attrs: sftpwire.Attrs{
				Flags: sftpwire.AttrUIDGID, UID: uint32(os.Getuid()) + 1, GID: uint32(os.Getgid()),
			}})},
			{"setstat nothing", req(&sftpwire.SetStat{Path: "a.txt"})},
			{"setstat a missing file", req(&sftpwire.SetStat{Path: "missing", Attrs: perms(0o644)})},
			{"truncate a directory", req(&sftpwire.SetStat{Path: "d", Attrs: size(0)})},
			{"open for fsetstat", open("a.txt", wr)},
			{"fsetstat", fsetstat("open for fsetstat", perms(0o600))},
			{"fsetstat the size", fsetstat("open for fsetstat", size(2))},
			{"close after fsetstat", closeHandle("open for fsetstat")},
			{"stat after fsetstat", req(&sftpwire.Stat{Path: "a.txt"})},
			{"open for reading to fsetstat", open("a.txt", rd)},
			{"fsetstat the size through a handle open for reading", fsetstat("open for reading to fsetstat", size(1))},
			{"close after the read-only fsetstat", closeHandle("open for reading to fsetstat")},
			{"stat after the read-only fsetstat", req(&sftpwire.Stat{Path: "a.txt"})},
		},
	),
	"directories": concat(
		[]step{
			{"mkdir", req(&sftpwire.Mkdir{Path: "d"})},
			{"mkdir an existing directory", req(&sftpwire.Mkdir{Path: "d"})},
			{"mkdir in a missing directory", req(&sftpwire.Mkdir{Path: "missing/d"})},
			{"mkdir with permissions", req(&sftpwire.Mkdir{Path: "p", Attrs: perms(0o700)})},
			{"stat the directory made with permissions", req(&sftpwire.Stat{Path: "p"})},
		},
		file("d/a.txt", "a"),
		[]step{
			{"set times to list", req(&sftpwire.SetStat{Path: "d/a.txt", Attrs: stamped})},
			{"mkdir a subdirectory", req(&sftpwire.Mkdir{Path: "d/sub"})},
			{"stat a directory", req(&sftpwire.Stat{Path: "d"})},
			{"opendir", req(&sftpwire.OpenDir{Path: "d"})},
			{"readdir", readdir("opendir")},
			{"readdir at the end", readdir("opendir")},
			{"close the directory", closeHandle("opendir")},
			{"opendir a missing directory", req(&sftpwire.OpenDir{Path: "missing"})},
			{"opendir a file", req(&sftpwire.OpenDir{Path: "d/a.txt"})},
			{"rmdir a directory that is not empty", req(&sftpwire.Rmdir{Path: "d"})},
			{"rmdir a file", req(&sftpwire.Rmdir{Path: "d/a.txt"})},
			{"rmdir a missing directory", req(&sftpwire.Rmdir{Path: "missing"})},
			{"rmdir", req(&sftpwire.Rmdir{Path: "d/sub"})},
			{"remove a directory", req(&sftpwire.Remove{Path: "d"})},
			{"remove a missing file", req(&sftpwire.Remove{Path: "missing"})},
			{"remove", req(&sftpwire.Remove{Path: "d/a.txt"})},
		},
	),
	"renames": concat(
		file("a.txt", "a"),
		file("b.txt", "b"),
		[]step{
			{"mkdir d", req(&sftpwire.Mkdir{Path: "d"})},
			{"mkdir empty", req(&sftpwire.Mkdir{Path: "empty"})},
			{"mkdir full", req(&sftpwire.Mkdir{Path: "full"})},
		},
		file("full/f.txt", "f"),
		[]step{
			{"rename", req(&sftpwire.Rename{OldPath: "a.txt", NewPath: "c.txt"})},
			{"rename onto an existing file", req(&sftpwire.Rename{OldPath: "c.txt", NewPath: "b.txt"})},
			{"rename onto itself", req(&sftpwire.Rename{OldPath: "c.txt", NewPath: "c.txt"})},
			{"rename a missing file", req(&sftpwire.Rename{OldPath: "missing", NewPath: "x"})},
			{"rename into a missing directory", req(&sftpwire.Rename{OldPath: "c.txt", NewPath: "missing/c.txt"})},
			{"rename a directory", req(&sftpwire.Rename{OldPath: "d", NewPath: "d2"})},
			{"rename a directory onto an empty one", req(&sftpwire.Rename{OldPath: "d2", NewPath: "empty"})},
			{"posix-rename onto an existing file", req(&sftpwire.PosixRename{OldPath: "c.txt", NewPath: "b.txt"})},
			{"posix-rename a file onto a directory", req(&sftpwire.PosixRename{OldPath: "b.txt", NewPath: "full"})},
			{"posix-rename a directory onto a full one", req(&sftpwire.PosixRename{OldPath: "d2", NewPath: "full"})},
			{"posix-rename a missing file", req(&sftpwire.PosixRename{OldPath: "missing", NewPath: "x"})},
		},
	),
	// A difference that leaves different files has a script of its own, so
	// that the files of the others can still be compared.
	"replacing an empty directory": {
		{"mkdir the source", req(&sftpwire.Mkdir{Path: "source"})},
		{"mkdir the target", req(&sftpwire.Mkdir{Path: "target"})},
		{"posix-rename a directory onto an empty one", req(&sftpwire.PosixRename{OldPath: "source", NewPath: "target"})},
	},
	"paths": concat(
		file("a.txt", "a"),
		[]step{
			{"mkdir", req(&sftpwire.Mkdir{Path: "d"})},
			{"realpath of the start", req(&sftpwire.RealPath{Path: "."})},
			{"realpath of an empty path", req(&sftpwire.RealPath{Path: ""})},
			{"realpath through a parent", req(&sftpwire.RealPath{Path: "d/../a.txt"})},
			{"realpath of a missing file", req(&sftpwire.RealPath{Path: "missing"})},
			{"stat with a trailing slash", req(&sftpwire.Stat{Path: "d/"})},
			{"stat a file with a trailing slash", req(&sftpwire.Stat{Path: "a.txt/"})},
			{"stat through a file", req(&sftpwire.Stat{Path: "a.txt/x"})},
			{"stat through a missing directory", req(&sftpwire.Stat{Path: "missing/../a.txt"})},
			{"stat with doubled slashes", req(&sftpwire.Stat{Path: "d//..//a.txt"})},
			{"statvfs", req(&sftpwire.StatVFS{Path: "."})},
			{"statvfs a missing path", req(&sftpwire.StatVFS{Path: "missing"})},
		},
	),
	"names": concat(
		file("with space.txt", "space"),
		file("café.csv", "unicode"),
		file("Orders.csv", "capital"),
		file("orders.csv", "lowercase"),
		file(`back\slash.txt`, "backslash"),
		file("a:b.csv", "colon"),
		file("trailing.", "dot"),
		file("con.txt", "device"),
		file(strings.Repeat("n", 255), "longest"),
		[]step{
			{"create a name too long for any host", open(strings.Repeat("n", 256), create)},
			{"mkdir a name of 128 capitals", req(&sftpwire.Mkdir{Path: strings.Repeat("N", 128)})},
			{"rmdir the name of 128 capitals", req(&sftpwire.Rmdir{Path: strings.Repeat("N", 128)})},
		},
	),
}

func concat(parts ...[]step) []step {
	var steps []step
	for _, p := range parts {
		steps = append(steps, p...)
	}
	return steps
}

// differences are the steps whose replies from sftpit knowingly differ from
// OpenSSH's, by script and step, the steps whose longnames do, by script,
// step and "longnames", and the scripts whose files do, by script and
// "files", each with the reason.
var differences = map[string]string{
	"open flags/stat the file created with setuid": "the setuid, setgid and sticky bits are dropped, so a client cannot leave a setuid program in the developer's workspace",

	"directories/readdir longnames": "pkg/sftp formats longnames, giving the owner and group as numbers where OpenSSH names them, and the day unpadded",

	"setstat/stat after chmod with setuid": "the setuid, setgid and sticky bits are dropped, so a client cannot leave a setuid program in the developer's workspace",

	"replacing an empty directory/posix-rename a directory onto an empty one": "os.Root refuses to rename onto a directory, which rename(2) replaces when it is empty",

	"replacing an empty directory/files": "the source directory is left where it was",

	"paths/stat a file with a trailing slash": "pkg/sftp's request server cleans paths before the backend sees them, so a trailing slash after a file is ignored",

	"paths/stat through a missing directory": "pkg/sftp's request server cleans paths before the backend sees them, so .. after a missing directory is ignored",

	"names/mkdir a name of 128 capitals": "names are encoded on the host, so a name of more than 127 capitals is too long to store",

	"names/rmdir the name of 128 capitals": "names are encoded on the host, so a name of more than 127 capitals is too long to store",
}

// TestRepliesMatchOpenSSH runs each script against sftpit, directly and
// through the proxy, and against OpenSSH. sftpit must give the same replies
// both ways, and OpenSSH's apart from the listed differences, and the
// servers must end with the same files.
func TestRepliesMatchOpenSSH(t *testing.T) {
	server := sftpServer(t)
	for name, steps := range scripts {
		t.Run(name, func(t *testing.T) {
			targets := []*target{sftpitTarget(t, false), openSSHTarget(t, server), sftpitTarget(t, true)}
			var outcomes [3][]outcome
			for i, target := range targets {
				s := startSession(t, target)
				for _, st := range steps {
					p := st.request(s.handles)
					reply := s.send(p)
					if h, ok := reply.(*sftpwire.HandleReply); ok {
						s.handles[st.name] = h.Handle
					}
					outcomes[i] = append(outcomes[i], s.describe(p, reply))
				}
			}
			for i, st := range steps {
				sftpit, openSSH, proxied := outcomes[0][i], outcomes[1][i], outcomes[2][i]
				if sftpit != proxied {
					t.Errorf("%s: the proxy changed the reply\n  directly:          %+v\n  through the proxy: %+v", st.name, sftpit, proxied)
				}
				key := name + "/" + st.name
				compare(t, key, sftpit.reply, openSSH.reply)
				if sftpit.longnames != "" && openSSH.longnames != "" {
					compare(t, key+" longnames", sftpit.longnames, openSSH.longnames)
				}
			}
			trees := make([]string, len(targets))
			for i, target := range targets {
				trees[i] = strings.Join(tree(t, target), "\n")
			}
			if trees[0] != trees[2] {
				t.Errorf("the proxy changed the files\n--- directly\n%s\n--- through the proxy\n%s", trees[0], trees[2])
			}
			compare(t, name+"/files", trees[0], trees[1])
		})
	}
}

// compare requires sftpit's result for key to match OpenSSH's unless the
// difference is listed, and a listed difference to remain.
func compare(t *testing.T, key, sftpit, openSSH string) {
	t.Helper()
	reason, listed := differences[key]
	switch {
	case sftpit == openSSH && listed:
		t.Errorf("%s no longer differs from OpenSSH, so it should leave the list of differences", key)
	case sftpit != openSSH && !listed:
		t.Errorf("%s differs from OpenSSH\n--- sftpit\n%s\n--- OpenSSH\n%s", key, sftpit, openSSH)
	case listed:
		t.Logf("%s differs, as listed, because %s\n--- sftpit\n%s\n--- OpenSSH\n%s", key, reason, sftpit, openSSH)
	}
}

func TestExtensionsAreOpenSSHs(t *testing.T) {
	sftpit := startSession(t, sftpitTarget(t, false))
	openSSH := startSession(t, openSSHTarget(t, sftpServer(t)))
	for _, ext := range sftpit.version.Extensions {
		if !slices.Contains(openSSH.version.Extensions, ext) {
			t.Errorf("sftpit offers %s version %s, which OpenSSH does not; OpenSSH offers %v", ext.Name, ext.Data, openSSH.version.Extensions)
		}
	}
	if sftpit.version.Version != openSSH.version.Version {
		t.Errorf("sftpit speaks version %d, OpenSSH %d", sftpit.version.Version, openSSH.version.Version)
	}
}
