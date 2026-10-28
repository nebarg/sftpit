package sftpwire

import (
	"encoding/binary"
	"fmt"
)

// Init is SSH_FXP_INIT, the client's first packet.
type Init struct {
	Version    uint32
	Extensions []Extension
}

// Extension is an extension's name and data, as advertised in Init or
// Version. OpenSSH's extensions carry their version in Data.
type Extension struct {
	Name string
	Data string
}

// AppendInit appends p to b as a complete packet.
func AppendInit(b []byte, p Init) []byte {
	b, start := startPacket(b, TypeInit)
	b = binary.BigEndian.AppendUint32(b, p.Version)
	b = appendExtensions(b, p.Extensions)
	return finishPacket(b, start)
}

// DecodeInit decodes a packet read by ReadPacket, which must be SSH_FXP_INIT.
func DecodeInit(b []byte) (Init, error) {
	d := decoder{b: b}
	if t := PacketType(d.uint8()); t != TypeInit {
		return Init{}, fmt.Errorf("sftpwire: got %v, want %v", t, TypeInit)
	}
	p := Init{Version: d.uint32(), Extensions: d.extensions()}
	if d.err != nil {
		return Init{}, malformed(TypeInit)
	}
	return p, nil
}

// Open is SSH_FXP_OPEN, which opens or creates the file at Path.
type Open struct {
	Path  string
	Flags uint32 // Open* bits
	Attrs Attrs  // for a file it creates
}

// Close is SSH_FXP_CLOSE.
type Close struct {
	Handle string
}

// Read is SSH_FXP_READ, which reads up to Length bytes at Offset.
type Read struct {
	Handle string
	Offset uint64
	Length uint32
}

// Write is SSH_FXP_WRITE.
type Write struct {
	Handle string
	Offset uint64
	Data   []byte
}

// LStat is SSH_FXP_LSTAT, which does not follow a final symbolic link.
type LStat struct {
	Path string
}

// FStat is SSH_FXP_FSTAT.
type FStat struct {
	Handle string
}

// SetStat is SSH_FXP_SETSTAT.
type SetStat struct {
	Path  string
	Attrs Attrs
}

// FSetStat is SSH_FXP_FSETSTAT.
type FSetStat struct {
	Handle string
	Attrs  Attrs
}

// OpenDir is SSH_FXP_OPENDIR.
type OpenDir struct {
	Path string
}

// ReadDir is SSH_FXP_READDIR, which reads the next entries of an open
// directory.
type ReadDir struct {
	Handle string
}

// Remove is SSH_FXP_REMOVE, which removes a file.
type Remove struct {
	Path string
}

// Mkdir is SSH_FXP_MKDIR.
type Mkdir struct {
	Path  string
	Attrs Attrs
}

// Rmdir is SSH_FXP_RMDIR.
type Rmdir struct {
	Path string
}

// RealPath is SSH_FXP_REALPATH, which asks the server to canonicalize Path.
type RealPath struct {
	Path string
}

// Stat is SSH_FXP_STAT.
type Stat struct {
	Path string
}

// Rename is SSH_FXP_RENAME, which fails if NewPath exists.
type Rename struct {
	OldPath string
	NewPath string
}

// PosixRename is the posix-rename@openssh.com extended request, which
// replaces NewPath if it exists.
type PosixRename struct {
	OldPath string
	NewPath string
}

// StatVFS is the statvfs@openssh.com extended request.
type StatVFS struct {
	Path string
}

// Type returns TypeOpen.
func (*Open) Type() PacketType { return TypeOpen }

// Type returns TypeClose.
func (*Close) Type() PacketType { return TypeClose }

// Type returns TypeRead.
func (*Read) Type() PacketType { return TypeRead }

// Type returns TypeWrite.
func (*Write) Type() PacketType { return TypeWrite }

// Type returns TypeLStat.
func (*LStat) Type() PacketType { return TypeLStat }

// Type returns TypeFStat.
func (*FStat) Type() PacketType { return TypeFStat }

// Type returns TypeSetStat.
func (*SetStat) Type() PacketType { return TypeSetStat }

// Type returns TypeFSetStat.
func (*FSetStat) Type() PacketType { return TypeFSetStat }

// Type returns TypeOpenDir.
func (*OpenDir) Type() PacketType { return TypeOpenDir }

// Type returns TypeReadDir.
func (*ReadDir) Type() PacketType { return TypeReadDir }

// Type returns TypeRemove.
func (*Remove) Type() PacketType { return TypeRemove }

// Type returns TypeMkdir.
func (*Mkdir) Type() PacketType { return TypeMkdir }

// Type returns TypeRmdir.
func (*Rmdir) Type() PacketType { return TypeRmdir }

// Type returns TypeRealPath.
func (*RealPath) Type() PacketType { return TypeRealPath }

// Type returns TypeStat.
func (*Stat) Type() PacketType { return TypeStat }

// Type returns TypeRename.
func (*Rename) Type() PacketType { return TypeRename }

// Type returns TypeExtended.
func (*PosixRename) Type() PacketType { return TypeExtended }

// Type returns TypeExtended.
func (*StatVFS) Type() PacketType { return TypeExtended }

func (p *Open) appendBody(b []byte) []byte {
	b = appendString(b, p.Path)
	b = binary.BigEndian.AppendUint32(b, p.Flags)
	return appendAttrs(b, p.Attrs)
}

func (p *Close) appendBody(b []byte) []byte {
	return appendString(b, p.Handle)
}

func (p *Read) appendBody(b []byte) []byte {
	b = appendString(b, p.Handle)
	b = binary.BigEndian.AppendUint64(b, p.Offset)
	return binary.BigEndian.AppendUint32(b, p.Length)
}

func (p *Write) appendBody(b []byte) []byte {
	b = appendString(b, p.Handle)
	b = binary.BigEndian.AppendUint64(b, p.Offset)
	return appendString(b, p.Data)
}

func (p *LStat) appendBody(b []byte) []byte {
	return appendString(b, p.Path)
}

func (p *FStat) appendBody(b []byte) []byte {
	return appendString(b, p.Handle)
}

func (p *SetStat) appendBody(b []byte) []byte {
	b = appendString(b, p.Path)
	return appendAttrs(b, p.Attrs)
}

func (p *FSetStat) appendBody(b []byte) []byte {
	b = appendString(b, p.Handle)
	return appendAttrs(b, p.Attrs)
}

func (p *OpenDir) appendBody(b []byte) []byte {
	return appendString(b, p.Path)
}

func (p *ReadDir) appendBody(b []byte) []byte {
	return appendString(b, p.Handle)
}

func (p *Remove) appendBody(b []byte) []byte {
	return appendString(b, p.Path)
}

func (p *Mkdir) appendBody(b []byte) []byte {
	b = appendString(b, p.Path)
	return appendAttrs(b, p.Attrs)
}

func (p *Rmdir) appendBody(b []byte) []byte {
	return appendString(b, p.Path)
}

func (p *RealPath) appendBody(b []byte) []byte {
	return appendString(b, p.Path)
}

func (p *Stat) appendBody(b []byte) []byte {
	return appendString(b, p.Path)
}

func (p *Rename) appendBody(b []byte) []byte {
	b = appendString(b, p.OldPath)
	return appendString(b, p.NewPath)
}

func (p *PosixRename) appendBody(b []byte) []byte {
	b = appendString(b, ExtPosixRename)
	b = appendString(b, p.OldPath)
	return appendString(b, p.NewPath)
}

func (p *StatVFS) appendBody(b []byte) []byte {
	b = appendString(b, ExtStatVFS)
	return appendString(b, p.Path)
}

// DecodeRequest decodes a client request read by ReadPacket and returns its
// request ID. A version 3 request or extended request that sftpit does not
// implement returns an *UnsupportedError carrying the ID. Any other error
// means the packet is malformed or is not a request. Write.Data shares b's
// memory.
func DecodeRequest(b []byte) (uint32, Packet, error) {
	d := decoder{b: b}
	t := PacketType(d.uint8())
	id := d.uint32()
	if d.err != nil {
		return 0, nil, malformed(t)
	}

	var p Packet
	switch t {
	case TypeOpen:
		p = &Open{Path: d.path(), Flags: d.uint32(), Attrs: d.attrs()}
	case TypeClose:
		p = &Close{Handle: d.string()}
	case TypeRead:
		p = &Read{Handle: d.string(), Offset: d.uint64(), Length: d.uint32()}
	case TypeWrite:
		p = &Write{Handle: d.string(), Offset: d.uint64(), Data: d.bytes()}
	case TypeLStat:
		p = &LStat{Path: d.path()}
	case TypeFStat:
		p = &FStat{Handle: d.string()}
	case TypeSetStat:
		p = &SetStat{Path: d.path(), Attrs: d.attrs()}
	case TypeFSetStat:
		p = &FSetStat{Handle: d.string(), Attrs: d.attrs()}
	case TypeOpenDir:
		p = &OpenDir{Path: d.path()}
	case TypeReadDir:
		p = &ReadDir{Handle: d.string()}
	case TypeRemove:
		p = &Remove{Path: d.path()}
	case TypeMkdir:
		p = &Mkdir{Path: d.path(), Attrs: d.attrs()}
	case TypeRmdir:
		p = &Rmdir{Path: d.path()}
	case TypeRealPath:
		p = &RealPath{Path: d.path()}
	case TypeStat:
		p = &Stat{Path: d.path()}
	case TypeRename:
		p = &Rename{OldPath: d.path(), NewPath: d.path()}
	case TypeReadLink, TypeSymlink:
		return 0, nil, &UnsupportedError{ID: id, Type: t}
	case TypeExtended:
		switch name := d.string(); name {
		case ExtPosixRename:
			p = &PosixRename{OldPath: d.path(), NewPath: d.path()}
		case ExtStatVFS:
			p = &StatVFS{Path: d.path()}
		default:
			if d.err == nil {
				return 0, nil, &UnsupportedError{ID: id, Type: t, Extension: name}
			}
		}
	default:
		return 0, nil, fmt.Errorf("sftpwire: %v is not a request", t)
	}
	if d.err != nil {
		return 0, nil, malformed(t)
	}
	return id, p, nil
}
