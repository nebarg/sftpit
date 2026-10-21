package sftpproxy

import (
	"context"
	"log/slog"
	"math"
	"slices"

	"github.com/nebarg/sftpit/internal/sftpwire"
)

// download is a CorruptDownload on an open handle.
type download struct {
	CorruptDownload

	// corrupted is set once the corruption has changed a read on the handle,
	// and declined if Reserve refused the first change.
	corrupted, declined bool
}

// split is a READ that crosses an omitted range, which reaches the backend
// as two reads: whole, the READ itself shortened to end at the range, and
// rest, of the bytes after the range. The client gets one reply once the
// backend has answered both.
type split struct {
	whole, rest *request

	// before and after are the backend's replies to whole and rest.
	before, after sftpwire.Packet
}

// corrupt applies the corruption on req's handle if req is a read that it
// changes, and reports whether it did. Only the first read it changes is
// logged as a fault; the reads it changes after that are its effects.
func (s *session) corrupt(req *request) bool {
	r, ok := req.packet.(*sftpwire.Read)
	if !ok || req.download == nil || req.download.declined {
		return false
	}
	d := req.download
	if !d.changes(r) {
		return false
	}
	level := slog.LevelDebug
	if !d.corrupted {
		d.corrupted, level = true, slog.LevelInfo
		if d.Reserve != nil && !d.Reserve() {
			d.declined = true
			return false
		}
	}
	offset := r.Offset
	switch d.Corruption {
	case Truncate:
		if r.Offset >= d.Offset {
			req.eof = true
		} else {
			r.Length = uint32(d.Offset - r.Offset)
		}
	case OmitRange:
		switch {
		case r.Offset > math.MaxUint64-d.Length:
			// No file reaches this far.
			req.eof = true
		case r.Offset >= d.Offset:
			r.Offset += d.Length
		default:
			before := uint32(d.Offset - r.Offset)
			rest := &request{
				clientID: req.clientID,
				packet:   &sftpwire.Read{Handle: r.Handle, Offset: d.Offset + d.Length, Length: r.Length - before},
				path:     req.path,
				handle:   req.handle,
			}
			r.Length = before
			req.split = &split{whole: req, rest: rest}
			rest.split = req.split
		}
	case FlipBytes:
		req.flip = true
	}
	attrs := []any{"request", operation(r), "path", req.path, "fault", "corrupt_download", "corruption", d.Corruption, "at", d.Offset}
	if d.Corruption != Truncate {
		attrs = append(attrs, "length", d.Length)
	}
	s.logger.Log(context.Background(), level, "injected fault", append(attrs, "offset", offset)...)
	return true
}

// changes reports whether the corruption changes what r returns. Truncate
// and OmitRange change every read that reaches Offset, and FlipBytes every
// read that overlaps the flipped bytes.
func (d *download) changes(r *sftpwire.Read) bool {
	reaches := r.Offset >= d.Offset || uint64(r.Length) > d.Offset-r.Offset
	if d.Corruption == FlipBytes {
		return reaches && r.Offset < d.Offset+d.Length
	}
	return reaches
}

// joinReads returns the request that req, answered by the backend with p,
// belongs to and the reply for the client. If req is one of a split READ's
// two backend reads and the other has yet to be answered, it returns nil.
func joinReads(req *request, p sftpwire.Packet) (*request, sftpwire.Packet) {
	sp := req.split
	if sp == nil {
		return req, p
	}
	if req == sp.whole {
		sp.before = p
	} else {
		sp.after = p
	}
	if sp.before == nil || sp.after == nil {
		return nil, nil
	}
	return sp.whole, sp.joined()
}

// joined returns the reply to a split READ: the bytes on both sides of the
// omitted range or, if the backend has not returned all the bytes before it
// or has none after it, the reply that ends first, as a read that reaches
// the end of the file does.
func (sp *split) joined() sftpwire.Packet {
	before, ok := sp.before.(*sftpwire.DataReply)
	if !ok || len(before.Data) < int(sp.whole.packet.(*sftpwire.Read).Length) {
		return sp.before
	}
	after, ok := sp.after.(*sftpwire.DataReply)
	if !ok {
		return before
	}
	return &sftpwire.DataReply{Data: slices.Concat(before.Data, after.Data)}
}

// flipBytes flips the bits of p, the backend's reply to req, that a
// FlipBytes corruption on req's handle changes.
func flipBytes(req *request, p sftpwire.Packet) {
	d := req.download
	data, ok := p.(*sftpwire.DataReply)
	if !req.flip || !ok {
		return
	}
	offset := req.packet.(*sftpwire.Read).Offset
	for i := range data.Data {
		if at := offset + uint64(i); at >= d.Offset && at-d.Offset < d.Length {
			data.Data[i] ^= 1
		}
	}
}
