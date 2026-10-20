package sftpwire_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"sftpit/internal/sftpwire"
)

const maxLength = 256 * 1024

var fullAttrs = sftpwire.Attrs{
	Flags: sftpwire.AttrSize | sftpwire.AttrUIDGID | sftpwire.AttrPermissions |
		sftpwire.AttrACModTime | sftpwire.AttrExtended,
	Size:        1 << 40,
	UID:         501,
	GID:         20,
	Permissions: 0o100644,
	ATime:       1_700_000_000,
	MTime:       1_700_000_001,
	Extended:    []sftpwire.ExtendedAttr{{Type: "acl@example.com", Data: "\x00\x01"}},
}

var requests = []sftpwire.Packet{
	&sftpwire.Open{Path: "/in/a.csv", Flags: sftpwire.OpenWrite | sftpwire.OpenCreate | sftpwire.OpenTruncate, Attrs: fullAttrs},
	&sftpwire.Open{Path: "relative/b.csv", Flags: sftpwire.OpenRead},
	&sftpwire.Close{Handle: "\x00\x00\x00\x01"},
	&sftpwire.Read{Handle: "1", Offset: 1 << 33, Length: 32768},
	&sftpwire.Write{Handle: "1", Offset: 7, Data: []byte("hello\x00world")},
	&sftpwire.Write{Handle: "1", Offset: 0},
	&sftpwire.LStat{Path: "/in"},
	&sftpwire.FStat{Handle: "1"},
	&sftpwire.SetStat{Path: "/in/a.csv", Attrs: sftpwire.Attrs{Flags: sftpwire.AttrPermissions, Permissions: 0o600}},
	&sftpwire.FSetStat{Handle: "1", Attrs: sftpwire.Attrs{Flags: sftpwire.AttrACModTime, ATime: 1, MTime: 2}},
	&sftpwire.OpenDir{Path: "/in"},
	&sftpwire.ReadDir{Handle: "2"},
	&sftpwire.Remove{Path: "/in/a.csv"},
	&sftpwire.Mkdir{Path: "/out", Attrs: sftpwire.Attrs{Flags: sftpwire.AttrPermissions, Permissions: 0o755}},
	&sftpwire.Rmdir{Path: "/out"},
	&sftpwire.RealPath{Path: "."},
	&sftpwire.Stat{Path: "/in/ünïcode name.csv"},
	&sftpwire.Rename{OldPath: "/in/a.part", NewPath: "/in/a.csv"},
	&sftpwire.PosixRename{OldPath: "/in/a.part", NewPath: "/in/a.csv"},
	&sftpwire.StatVFS{Path: "/"},
}

var replies = []sftpwire.Packet{
	&sftpwire.StatusReply{Code: sftpwire.StatusNoSuchFile, Message: "No such file"},
	&sftpwire.StatusReply{Code: sftpwire.StatusOK, Message: "Success", Language: "en"},
	&sftpwire.HandleReply{Handle: "\x00\x00\x00\x02"},
	&sftpwire.DataReply{Data: []byte{0, 1, 2, 255}},
	&sftpwire.NameReply{Entries: []sftpwire.NameEntry{
		{Filename: "a.csv", Longname: "-rw-r--r--    1 501      20             5 Oct 20 12:00 a.csv", Attrs: fullAttrs},
		{Filename: "b.csv"},
	}},
	&sftpwire.NameReply{},
	&sftpwire.AttrsReply{Attrs: fullAttrs},
	&sftpwire.AttrsReply{},
	&sftpwire.ExtendedReply{Data: bytes.Repeat([]byte{0, 0, 0, 0, 0, 0, 16, 0}, 11)},
}

func TestRequestRoundTrip(t *testing.T) {
	for _, want := range requests {
		t.Run(want.Type().String(), func(t *testing.T) {
			b := readOne(t, sftpwire.AppendPacket(nil, 42, want))
			id, got, err := sftpwire.DecodeRequest(b)
			if err != nil {
				t.Fatalf("DecodeRequest: %v", err)
			}
			if id != 42 || !reflect.DeepEqual(got, want) {
				t.Errorf("decoded id %d %#v, want id 42 %#v", id, got, want)
			}
		})
	}
}

func TestReplyRoundTrip(t *testing.T) {
	for _, want := range replies {
		t.Run(want.Type().String(), func(t *testing.T) {
			b := readOne(t, sftpwire.AppendPacket(nil, 0xffffffff, want))
			id, got, err := sftpwire.DecodeReply(b)
			if err != nil {
				t.Fatalf("DecodeReply: %v", err)
			}
			if id != 0xffffffff || !reflect.DeepEqual(got, want) {
				t.Errorf("decoded id %d %#v, want id %d %#v", id, got, uint32(0xffffffff), want)
			}
		})
	}
}

func TestInitAndVersionRoundTrip(t *testing.T) {
	exts := []sftpwire.Extension{{Name: sftpwire.ExtPosixRename, Data: "1"}, {Name: sftpwire.ExtStatVFS, Data: "2"}}

	gotInit, err := sftpwire.DecodeInit(readOne(t, sftpwire.AppendInit(nil, sftpwire.Init{Version: 6, Extensions: exts})))
	if err != nil {
		t.Fatalf("DecodeInit: %v", err)
	}
	if want := (sftpwire.Init{Version: 6, Extensions: exts}); !reflect.DeepEqual(gotInit, want) {
		t.Errorf("DecodeInit = %#v, want %#v", gotInit, want)
	}

	version, err := sftpwire.DecodeVersion(readOne(t, sftpwire.AppendVersion(nil, sftpwire.Version{Version: 3})))
	if err != nil {
		t.Fatalf("DecodeVersion: %v", err)
	}
	if want := (sftpwire.Version{Version: 3}); !reflect.DeepEqual(version, want) {
		t.Errorf("DecodeVersion = %#v, want %#v", version, want)
	}

	if _, err := sftpwire.DecodeVersion(readOne(t, sftpwire.AppendInit(nil, sftpwire.Init{Version: 3}))); err == nil {
		t.Error("DecodeVersion accepted an INIT packet")
	}
}

// TestWireLayout checks encoded bytes against layouts written out from the
// draft, which a round trip alone would not catch if encoding and decoding
// shared a mistake.
func TestWireLayout(t *testing.T) {
	tests := []struct {
		name   string
		packet sftpwire.Packet
		want   wire
	}{
		{
			name:   "open",
			packet: &sftpwire.Open{Path: "/a", Flags: sftpwire.OpenWrite | sftpwire.OpenCreate, Attrs: sftpwire.Attrs{Flags: sftpwire.AttrPermissions, Permissions: 0o644}},
			want:   wire{}.byte(3).u32(7).str("/a").u32(0x0a).u32(0x04).u32(0o644),
		},
		{
			name:   "write",
			packet: &sftpwire.Write{Handle: "h", Offset: 1 << 32, Data: []byte("xy")},
			want:   wire{}.byte(6).u32(7).str("h").u64(1 << 32).str("xy"),
		},
		{
			name:   "read",
			packet: &sftpwire.Read{Handle: "h", Offset: 3, Length: 9},
			want:   wire{}.byte(5).u32(7).str("h").u64(3).u32(9),
		},
		{
			name:   "posix-rename",
			packet: &sftpwire.PosixRename{OldPath: "/a", NewPath: "/b"},
			want:   wire{}.byte(200).u32(7).str("posix-rename@openssh.com").str("/a").str("/b"),
		},
		{
			name:   "status",
			packet: &sftpwire.StatusReply{Code: sftpwire.StatusNoSuchFile, Message: "No such file"},
			want:   wire{}.byte(101).u32(7).u32(2).str("No such file").str(""),
		},
		{
			name: "name with every attribute",
			packet: &sftpwire.NameReply{Entries: []sftpwire.NameEntry{
				{Filename: "f", Longname: "l", Attrs: fullAttrs},
			}},
			want: wire{}.byte(104).u32(7).u32(1).str("f").str("l").
				u32(0x8000000f).u64(1 << 40).u32(501).u32(20).u32(0o100644).u32(1_700_000_000).u32(1_700_000_001).
				u32(1).str("acl@example.com").str("\x00\x01"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sftpwire.AppendPacket(nil, 7, tt.packet)
			if want := tt.want.framed(); !bytes.Equal(got, want) {
				t.Errorf("encoded\n%x\nwant\n%x", got, want)
			}
		})
	}
}

func TestDecodeRequestUnsupported(t *testing.T) {
	tests := []struct {
		name string
		b    wire
		want sftpwire.UnsupportedError
	}{
		{
			name: "readlink",
			b:    wire{}.byte(19).u32(10).str("/link"),
			want: sftpwire.UnsupportedError{ID: 10, Type: sftpwire.TypeReadLink},
		},
		{
			name: "symlink",
			b:    wire{}.byte(20).u32(11).str("/a").str("/b"),
			want: sftpwire.UnsupportedError{ID: 11, Type: sftpwire.TypeSymlink},
		},
		{
			name: "hardlink extension",
			b:    wire{}.byte(200).u32(12).str("hardlink@openssh.com").str("/a").str("/b"),
			want: sftpwire.UnsupportedError{ID: 12, Type: sftpwire.TypeExtended, Extension: "hardlink@openssh.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := sftpwire.DecodeRequest(tt.b)
			got, ok := errors.AsType[*sftpwire.UnsupportedError](err)
			if !ok {
				t.Fatalf("DecodeRequest error = %v, want an *UnsupportedError", err)
			}
			if *got != tt.want {
				t.Errorf("DecodeRequest error = %#v, want %#v", *got, tt.want)
			}
		})
	}
}

func TestDecodeRejectsMalformedPackets(t *testing.T) {
	tests := []struct {
		name   string
		decode func([]byte) error
		b      wire
	}{
		{name: "request without an ID", decode: decodeRequest, b: wire{}.byte(17).u32(0)[:3]},
		{name: "truncated path", decode: decodeRequest, b: wire{}.byte(17).u32(1).u32(10).bytes("/a")},
		{name: "open without attributes", decode: decodeRequest, b: wire{}.byte(3).u32(1).str("/a").u32(1)},
		{name: "NUL in a path", decode: decodeRequest, b: wire{}.byte(17).u32(1).str("/a\x00b")},
		{name: "NUL in a rename target", decode: decodeRequest, b: wire{}.byte(18).u32(1).str("/a").str("/b\x00")},
		{name: "truncated extension name", decode: decodeRequest, b: wire{}.byte(200).u32(1).u32(30).bytes("statvfs")},
		{name: "extension without its fields", decode: decodeRequest, b: wire{}.byte(200).u32(1).str(sftpwire.ExtStatVFS)},
		{name: "attribute flags without their fields", decode: decodeRequest, b: wire{}.byte(9).u32(1).str("/a").u32(sftpwire.AttrSize).u32(0)},
		{name: "extended attribute count past the end", decode: decodeRequest, b: wire{}.byte(9).u32(1).str("/a").u32(sftpwire.AttrExtended).u32(0x7fffffff)},
		{name: "name count past the end", decode: decodeReply, b: wire{}.byte(104).u32(1).u32(0x7fffffff)},
		{name: "status without a language tag", decode: decodeReply, b: wire{}.byte(101).u32(1).u32(0).str("Success")},
		{name: "truncated version extension", decode: decodeVersion, b: wire{}.byte(2).u32(3).str(sftpwire.ExtStatVFS)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.decode(tt.b); !errors.Is(err, sftpwire.ErrMalformed) {
				t.Errorf("decode error = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestDecodeRejectsWrongPacketKind(t *testing.T) {
	tests := []struct {
		name   string
		decode func([]byte) error
		b      wire
	}{
		{name: "reply as a request", decode: decodeRequest, b: wire{}.byte(101).u32(1).u32(0).str("").str("")},
		{name: "INIT as a request", decode: decodeRequest, b: wire{}.byte(1).u32(3)},
		{name: "unknown request type", decode: decodeRequest, b: wire{}.byte(99).u32(1)},
		{name: "request as a reply", decode: decodeReply, b: wire{}.byte(17).u32(1).str("/a")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.decode(tt.b)
			if err == nil {
				t.Fatal("decode succeeded, want an error")
			}
			if _, ok := errors.AsType[*sftpwire.UnsupportedError](err); ok {
				t.Errorf("decode error = %v, want an error the session cannot answer", err)
			}
		})
	}
}

func TestDecodeIgnoresTrailingBytes(t *testing.T) {
	id, p, err := sftpwire.DecodeRequest(wire{}.byte(17).u32(5).str("/a").bytes("\x01\x02\x03"))
	if err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}
	if want := (&sftpwire.Stat{Path: "/a"}); id != 5 || !reflect.DeepEqual(p, want) {
		t.Errorf("DecodeRequest = %d %#v, want 5 %#v", id, p, want)
	}
}

func TestDecodeKeepsUndefinedAttributeFlags(t *testing.T) {
	_, p, err := sftpwire.DecodeRequest(wire{}.byte(9).u32(5).str("/a").u32(0x14).u32(0o600))
	if err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}
	want := &sftpwire.SetStat{Path: "/a", Attrs: sftpwire.Attrs{Flags: 0x14, Permissions: 0o600}}
	if !reflect.DeepEqual(p, want) {
		t.Errorf("DecodeRequest = %#v, want %#v", p, want)
	}
}

func TestReadPacket(t *testing.T) {
	stat := wire{}.byte(17).u32(1).str("/a")

	tests := []struct {
		name    string
		input   []byte
		want    []byte
		wantErr error
	}{
		{name: "one packet", input: stat.framed(), want: stat},
		{name: "end before a packet", input: nil, wantErr: io.EOF},
		{name: "end inside the length", input: []byte{0, 0}, wantErr: io.ErrUnexpectedEOF},
		{name: "end inside the body", input: stat.framed()[:8], wantErr: io.ErrUnexpectedEOF},
		{name: "empty packet", input: wire{}.u32(0), wantErr: sftpwire.ErrMalformed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sftpwire.ReadPacket(bytes.NewReader(tt.input), maxLength)
			if !errors.Is(err, tt.wantErr) || !bytes.Equal(got, tt.want) {
				t.Errorf("ReadPacket = %x, %v; want %x, %v", got, err, tt.want, tt.wantErr)
			}
		})
	}

	t.Run("packet over the limit", func(t *testing.T) {
		_, err := sftpwire.ReadPacket(bytes.NewReader(wire{}.u32(maxLength+1)), maxLength)
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Errorf("ReadPacket error = %v, want a length limit error", err)
		}
	})
}

func readOne(t *testing.T, framed []byte) []byte {
	t.Helper()
	r := bytes.NewReader(framed)
	b, err := sftpwire.ReadPacket(r, maxLength)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if r.Len() != 0 {
		t.Fatalf("ReadPacket left %d of %d bytes unread", r.Len(), len(framed))
	}
	return b
}

func decodeRequest(b []byte) error {
	_, _, err := sftpwire.DecodeRequest(b)
	return err
}

func decodeReply(b []byte) error {
	_, _, err := sftpwire.DecodeReply(b)
	return err
}

func decodeVersion(b []byte) error {
	_, err := sftpwire.DecodeVersion(b)
	return err
}

// wire builds packet bytes field by field, as the draft lays them out.
type wire []byte

func (w wire) byte(v byte) wire    { return append(w, v) }
func (w wire) u32(v uint32) wire   { return binary.BigEndian.AppendUint32(w, v) }
func (w wire) u64(v uint64) wire   { return binary.BigEndian.AppendUint64(w, v) }
func (w wire) str(s string) wire   { return append(w.u32(uint32(len(s))), s...) }
func (w wire) bytes(s string) wire { return append(w, s...) }

func (w wire) framed() []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(w))), w...)
}
