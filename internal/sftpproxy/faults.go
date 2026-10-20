package sftpproxy

import (
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

// Action is a fault for one request: a Delay, Stall, Fail, Drop or Freeze.
// What else an action holds back depends on the session's ReplyOrder.
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

func (a Delay) when() When  { return a.When }
func (a Stall) when() When  { return a.When }
func (a Fail) when() When   { return a.When }
func (a Drop) when() When   { return a.When }
func (a Freeze) when() When { return a.When }
