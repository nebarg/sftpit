package sftpwire

import "encoding/binary"

// Attribute flags, the SSH_FILEXFER_ATTR_* bits of Attrs.Flags.
const (
	AttrSize        = 0x00000001
	AttrUIDGID      = 0x00000002
	AttrPermissions = 0x00000004
	AttrACModTime   = 0x00000008
	AttrExtended    = 0x80000000
)

// Attrs are file attributes. Each group of fields is on the wire only when
// its bit is set in Flags. Flags is kept as received, including bits that
// version 3 does not define, which carry no fields.
type Attrs struct {
	Flags       uint32
	Size        uint64
	UID         uint32
	GID         uint32
	Permissions uint32
	ATime       uint32
	MTime       uint32
	Extended    []ExtendedAttr
}

// ExtendedAttr is one vendor-specific attribute.
type ExtendedAttr struct {
	Type string
	Data string
}

func (d *decoder) attrs() Attrs {
	a := Attrs{Flags: d.uint32()}
	if a.Flags&AttrSize != 0 {
		a.Size = d.uint64()
	}
	if a.Flags&AttrUIDGID != 0 {
		a.UID = d.uint32()
		a.GID = d.uint32()
	}
	if a.Flags&AttrPermissions != 0 {
		a.Permissions = d.uint32()
	}
	if a.Flags&AttrACModTime != 0 {
		a.ATime = d.uint32()
		a.MTime = d.uint32()
	}
	if a.Flags&AttrExtended != 0 {
		for range d.count(8) {
			a.Extended = append(a.Extended, ExtendedAttr{Type: d.string(), Data: d.string()})
		}
	}
	return a
}

func appendAttrs(b []byte, a Attrs) []byte {
	b = binary.BigEndian.AppendUint32(b, a.Flags)
	if a.Flags&AttrSize != 0 {
		b = binary.BigEndian.AppendUint64(b, a.Size)
	}
	if a.Flags&AttrUIDGID != 0 {
		b = binary.BigEndian.AppendUint32(b, a.UID)
		b = binary.BigEndian.AppendUint32(b, a.GID)
	}
	if a.Flags&AttrPermissions != 0 {
		b = binary.BigEndian.AppendUint32(b, a.Permissions)
	}
	if a.Flags&AttrACModTime != 0 {
		b = binary.BigEndian.AppendUint32(b, a.ATime)
		b = binary.BigEndian.AppendUint32(b, a.MTime)
	}
	if a.Flags&AttrExtended != 0 {
		b = binary.BigEndian.AppendUint32(b, uint32(len(a.Extended)))
		for _, ext := range a.Extended {
			b = appendString(b, ext.Type)
			b = appendString(b, ext.Data)
		}
	}
	return b
}
