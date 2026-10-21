package sftpproxy

import (
	"fmt"
	"math"
	"time"

	"github.com/nebarg/sftpit/internal/sftpwire"
)

// Request describes a client request to Options.Faults.
type Request struct {
	// Packet is the decoded request, with its paths resolved. It must not be
	// modified.
	Packet sftpwire.Packet

	// Path is the canonical path the request acts on. For a request on a
	// handle, it is the path the handle was opened with, or empty if the
	// handle is unknown.
	Path string

	// Target is a rename's canonical destination.
	Target string

	// Entry is set when Faults is asked about one entry of a READDIR reply
	// rather than about a request: Packet is then the READDIR, and Path is
	// the entry's path. Only a WrongSize applies to an entry.
	Entry bool
}

// When says whether a fault takes effect before or after the backend acts on
// a request.
type When int

const (
	// Before applies a fault before the request reaches the backend, so the
	// request changes nothing there.
	Before When = iota

	// After applies a fault once the backend has acted on the request, so its
	// effect is committed whatever the client is told.
	After
)

func (w When) String() string {
	if w == After {
		return "after"
	}
	return "before"
}

// Action is a fault for one request: a Delay, Stall, Fail, Drop or Freeze,
// for an OPEN, a PartialUpload or CorruptDownload, or for a STAT, LSTAT,
// FSTAT or READDIR entry, a WrongSize. What else an action holds back
// depends on the session's ReplyOrder.
type Action interface {
	when() When
}

// Delay holds the request for Duration before the backend sees it, like a
// slow server, or holds its reply for Duration, like a slow reply to an
// operation that has already happened.
type Delay struct {
	When     When
	Duration time.Duration
}

// Stall holds the request or its reply as Delay does, until Release is closed
// or Limit passes, whichever comes first.
type Stall struct {
	When    When
	Release <-chan struct{}
	Limit   time.Duration
}

// Fail answers the request with Status. Before, the backend never sees the
// request. After, the backend has acted and its reply is discarded, so the
// client is told of a failure that did not happen.
type Fail struct {
	When   When
	Status sftpwire.StatusCode
}

// Drop closes the client's connection where the request's reply would be:
// every earlier reply is written first, and no later request reaches the
// backend. Before, the backend never sees the request; after, it has acted
// and its reply is lost. Reset makes the client see a TCP reset rather than a
// normal close.
type Drop struct {
	When  When
	Reset bool
}

// Freeze stops all traffic on the client's connection where Drop would close
// it, so the client sees neither replies nor a close and its SSH keepalives
// go unanswered. The connection is closed once Release is closed or Limit
// passes, whichever comes first.
type Freeze struct {
	When    When
	Release <-chan struct{}
	Limit   time.Duration
}

// PartialUpload, chosen for an OPEN, cuts off uploads through the handle it
// opens at Cutoff, so that no write on the handle changes a byte at or beyond
// it. Each write is decided by its offset and length alone. A write below
// Cutoff goes through. A write that crosses Cutoff is trimmed to the bytes
// below it and gets Result once the backend has stored them. A write at or
// beyond Cutoff gets Result without reaching the backend. Result is a Fail,
// Drop or Freeze, and its When is ignored.
//
// With a Fail, writes below Cutoff still succeed once the cutoff is reached,
// so a client that sends the whole file stores exactly its first Cutoff
// bytes, whatever order its writes arrive in. A Drop or Freeze takes effect
// at the first write that reaches Cutoff, so the same holds for a client that
// sends its writes in offset order.
type PartialUpload struct {
	Cutoff uint64
	Result Action

	// Reserve, if set, is called when a write on the handle first reaches
	// Cutoff, before anything is cut. If it returns false, the handle
	// carries on as if no PartialUpload had been chosen for it.
	Reserve func() bool
}

// CorruptDownload, chosen for an OPEN, corrupts what reads through the
// handle it opens return, while the file stays unchanged and every reply
// reports success. What a read returns depends only on the file and the
// read's own offset and length, so a client gets the same corrupted file
// however it splits and pipelines its reads.
type CorruptDownload struct {
	Corruption Corruption
	Offset     uint64

	// Length is how many bytes OmitRange or FlipBytes acts on.
	Length uint64

	// Reserve, if set, is called when the corruption would first change a
	// read on the handle, before it does. If it returns false, the handle
	// carries on as if no CorruptDownload had been chosen for it.
	Reserve func() bool
}

// Corruption is what a CorruptDownload does to a file's reads.
type Corruption int

const (
	// Truncate serves the file as if it ended at Offset. A read at or beyond
	// Offset gets EOF without reaching the backend, and a read that crosses
	// it ends there.
	Truncate Corruption = iota

	// OmitRange serves the file without the Length bytes at Offset, so that
	// every later byte comes Length bytes earlier. A read that crosses
	// Offset becomes two backend reads, of the bytes on either side, whose
	// data is joined, because a client that does not expect a short read
	// before the end of a file may skip bytes after one.
	OmitRange

	// FlipBytes flips the lowest bit of each of the Length bytes at Offset,
	// so that each one changes and text stays mostly printable.
	FlipBytes
)

func (c Corruption) String() string {
	switch c {
	case Truncate:
		return "truncate"
	case OmitRange:
		return "omit_range"
	case FlipBytes:
		return "flip_bytes"
	}
	return fmt.Sprintf("Corruption(%d)", int(c))
}

// WrongSize, chosen for a STAT, LSTAT or FSTAT, or for an entry of a
// READDIR reply, misreports the size in the backend's reply: as Size or, if
// Delta is not zero, as the true size plus Delta, but never below 0 or above
// the largest uint64. In a READDIR entry, the size in the longname changes
// too, if the longname shows the true size where ls -l does. The file itself
// is unchanged.
type WrongSize struct {
	Size  uint64
	Delta int64
}

// reported returns the size to report for a file of size actual.
func (a WrongSize) reported(actual uint64) uint64 {
	switch {
	case a.Delta > 0:
		return actual + min(uint64(a.Delta), math.MaxUint64-actual)
	case a.Delta < 0:
		// Negating in uint64 gives the magnitude even of math.MinInt64.
		return actual - min(-uint64(a.Delta), actual)
	}
	return a.Size
}

func (a Delay) when() When  { return a.When }
func (a Stall) when() When  { return a.When }
func (a Fail) when() When   { return a.When }
func (a Drop) when() When   { return a.When }
func (a Freeze) when() When { return a.When }

// A session takes a PartialUpload, CorruptDownload or WrongSize off its
// request before acting on any, so their when is never asked.
func (a PartialUpload) when() When   { return Before }
func (a CorruptDownload) when() When { return Before }
func (a WrongSize) when() When       { return Before }
