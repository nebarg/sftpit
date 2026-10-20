package sftpwire

import (
	"encoding/binary"
	"fmt"
)

// Version is SSH_FXP_VERSION, the server's answer to Init.
type Version struct {
	Version    uint32
	Extensions []Extension
}

// AppendVersion appends p to b as a complete packet.
func AppendVersion(b []byte, p Version) []byte {
	b, start := startPacket(b, TypeVersion)
	b = binary.BigEndian.AppendUint32(b, p.Version)
	b = appendExtensions(b, p.Extensions)
	return finishPacket(b, start)
}

// DecodeVersion decodes a packet read by ReadPacket, which must be
// SSH_FXP_VERSION.
func DecodeVersion(b []byte) (Version, error) {
	d := decoder{b: b}
	if t := PacketType(d.uint8()); t != TypeVersion {
		return Version{}, fmt.Errorf("sftpwire: got %v, want %v", t, TypeVersion)
	}
	p := Version{Version: d.uint32(), Extensions: d.extensions()}
	if d.err != nil {
		return Version{}, malformed(TypeVersion)
	}
	return p, nil
}

// StatusReply is SSH_FXP_STATUS, the result of a request that returns no
// other data, or the failure of any request.
type StatusReply struct {
	Code     StatusCode
	Message  string
	Language string
}

// HandleReply is SSH_FXP_HANDLE.
type HandleReply struct {
	Handle string
}

// DataReply is SSH_FXP_DATA.
type DataReply struct {
	Data []byte
}

// NameReply is SSH_FXP_NAME.
type NameReply struct {
	Entries []NameEntry
}

// NameEntry is one entry of a NameReply. Longname is the ls -l style line
// that READDIR replies carry.
type NameEntry struct {
	Filename string
	Longname string
	Attrs    Attrs
}

// AttrsReply is SSH_FXP_ATTRS.
type AttrsReply struct {
	Attrs Attrs
}

// ExtendedReply is SSH_FXP_EXTENDED_REPLY. Data is kept opaque because its
// format depends on the request.
type ExtendedReply struct {
	Data []byte
}

func (*StatusReply) Type() PacketType   { return TypeStatus }
func (*HandleReply) Type() PacketType   { return TypeHandle }
func (*DataReply) Type() PacketType     { return TypeData }
func (*NameReply) Type() PacketType     { return TypeName }
func (*AttrsReply) Type() PacketType    { return TypeAttrs }
func (*ExtendedReply) Type() PacketType { return TypeExtendedReply }

func (p *StatusReply) appendBody(b []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(p.Code))
	b = appendString(b, p.Message)
	return appendString(b, p.Language)
}

func (p *HandleReply) appendBody(b []byte) []byte {
	return appendString(b, p.Handle)
}

func (p *DataReply) appendBody(b []byte) []byte {
	return appendString(b, p.Data)
}

func (p *NameReply) appendBody(b []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(p.Entries)))
	for _, e := range p.Entries {
		b = appendString(b, e.Filename)
		b = appendString(b, e.Longname)
		b = appendAttrs(b, e.Attrs)
	}
	return b
}

func (p *AttrsReply) appendBody(b []byte) []byte {
	return appendAttrs(b, p.Attrs)
}

func (p *ExtendedReply) appendBody(b []byte) []byte {
	return append(b, p.Data...)
}

// DecodeReply decodes a server reply read by ReadPacket and returns the ID
// of the request it answers.
func DecodeReply(b []byte) (uint32, Packet, error) {
	d := decoder{b: b}
	t := PacketType(d.uint8())
	id := d.uint32()
	if d.err != nil {
		return 0, nil, malformed(t)
	}

	var p Packet
	switch t {
	case TypeStatus:
		p = &StatusReply{Code: StatusCode(d.uint32()), Message: d.string(), Language: d.string()}
	case TypeHandle:
		p = &HandleReply{Handle: d.string()}
	case TypeData:
		p = &DataReply{Data: d.bytes()}
	case TypeName:
		p = &NameReply{Entries: d.nameEntries()}
	case TypeAttrs:
		p = &AttrsReply{Attrs: d.attrs()}
	case TypeExtendedReply:
		p = &ExtendedReply{Data: d.rest()}
	default:
		return 0, nil, fmt.Errorf("sftpwire: %v is not a reply", t)
	}
	if d.err != nil {
		return 0, nil, malformed(t)
	}
	return id, p, nil
}

func (d *decoder) nameEntries() []NameEntry {
	var entries []NameEntry
	// Each entry is at least a filename, a longname and attribute flags.
	for range d.count(12) {
		entries = append(entries, NameEntry{Filename: d.string(), Longname: d.string(), Attrs: d.attrs()})
	}
	return entries
}
