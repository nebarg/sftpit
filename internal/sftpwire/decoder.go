package sftpwire

import (
	"encoding/binary"
	"strings"
)

// decoder reads big-endian fields from a packet. The first field that does
// not fit sets err, and every later read returns a zero value.
type decoder struct {
	b   []byte
	err error
}

func (d *decoder) fail() {
	if d.err == nil {
		d.err = ErrMalformed
	}
	d.b = nil
}

func (d *decoder) take(n uint32) []byte {
	if d.err != nil || uint64(n) > uint64(len(d.b)) {
		d.fail()
		return nil
	}
	v := d.b[:n:n]
	d.b = d.b[n:]
	return v
}

func (d *decoder) uint8() uint8 {
	if v := d.take(1); len(v) == 1 {
		return v[0]
	}
	return 0
}

func (d *decoder) uint32() uint32 {
	if v := d.take(4); len(v) == 4 {
		return binary.BigEndian.Uint32(v)
	}
	return 0
}

func (d *decoder) uint64() uint64 {
	if v := d.take(8); len(v) == 8 {
		return binary.BigEndian.Uint64(v)
	}
	return 0
}

// bytes returns a length-prefixed field without copying it, or nil if it is
// empty.
func (d *decoder) bytes() []byte {
	if v := d.take(d.uint32()); len(v) > 0 {
		return v
	}
	return nil
}

func (d *decoder) string() string {
	return string(d.take(d.uint32()))
}

func (d *decoder) path() string {
	s := d.string()
	if strings.IndexByte(s, 0) >= 0 {
		d.fail()
	}
	return s
}

// rest returns the unread bytes, or nil if there are none.
func (d *decoder) rest() []byte {
	if d.err != nil || len(d.b) == 0 {
		return nil
	}
	v := d.b[:len(d.b):len(d.b)]
	d.b = nil
	return v
}

// count reads an element count, rejecting counts that could not fit in the
// rest of the packet when each element takes at least minSize bytes.
func (d *decoder) count(minSize uint64) int {
	n := d.uint32()
	if uint64(n)*minSize > uint64(len(d.b)) {
		d.fail()
		return 0
	}
	return int(n)
}

func (d *decoder) extensions() []Extension {
	var exts []Extension
	for d.err == nil && len(d.b) > 0 {
		exts = append(exts, Extension{Name: d.string(), Data: d.string()})
	}
	return exts
}

func appendString[T ~string | ~[]byte](b []byte, s T) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

func appendExtensions(b []byte, exts []Extension) []byte {
	for _, ext := range exts {
		b = appendString(b, ext.Name)
		b = appendString(b, ext.Data)
	}
	return b
}
