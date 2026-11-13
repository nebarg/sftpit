// Package activity groups the events of a run into lines that say what
// clients did, as the dashboard's feed shows them: a connection, a login, a
// transfer with its reads or writes summed, a listing, or a single command,
// each with its outcome and the requests behind it. It says only what the
// server saw, never which client library did it.
package activity

import (
	"cmp"
	"slices"
	"strings"
	"time"

	"github.com/nebarg/sftpit/internal/events"
)

// The outcomes of a line or request.
const (
	OK = "ok"
	// ByFault means a fault caused it on purpose.
	ByFault = "fault"
	// Failed means it failed without a fault causing it.
	Failed = "failed"
)

// ConnectionClosed is the reason given for a request that never got a
// reply, or a transfer that its connection's end cut off.
const ConnectionClosed = "connection_closed"

// Line is one thing a client did, or that happened to the server.
type Line struct {
	// ID is that of the line's first event, and Time when it happened.
	ID   uint64    `json:"id"`
	Time time.Time `json:"time"`

	Connection uint64 `json:"connection,omitempty"`
	User       string `json:"user,omitempty"`

	// Kind says what it was: connected, disconnected, connection_failed,
	// upload, download, open, listing, check, delete, rename, mkdir,
	// rmdir, setstat, realpath, statvfs, outage, fault or other.
	Kind   string `json:"kind"`
	Path   string `json:"path,omitempty"`
	Target string `json:"target,omitempty"`

	// Outcome is ok, fault or failed, and Reason the reply that a fault or
	// failure gave, such as permission_denied, or connection_closed.
	Outcome string `json:"outcome"`
	Reason  string `json:"reason,omitempty"`
	Fault   *Fault `json:"fault,omitempty"`

	// ReadOnly is the read-only path that refused a request.
	ReadOnly string `json:"read_only,omitempty"`

	// Bytes is what a transfer moved, and Duration how long the line took:
	// a transfer from its open to its close, a connection from its login
	// to its end.
	Bytes    uint64        `json:"bytes,omitempty"`
	Duration events.Millis `json:"duration_ms,omitempty"`

	// Remote is the address a connection came from, and Client the
	// version its client announced.
	Remote string `json:"remote,omitempty"`
	Client string `json:"client,omitempty"`

	// InProgress is set for a transfer or listing that is still open.
	InProgress bool `json:"in_progress,omitempty"`

	// Repeat is the earlier download of the same file by the same user, if
	// there was one.
	Repeat *Repeat `json:"repeat,omitempty"`

	Requests []Request `json:"requests"`
}

// Fault names the fault that caused something.
type Fault struct {
	ID   string           `json:"id"`
	Name string           `json:"name"`
	Type events.FaultType `json:"type,omitempty"`
}

// Repeat points at an earlier line.
type Repeat struct {
	ID   uint64    `json:"id"`
	Time time.Time `json:"time"`
}

// Request is a request behind a line, or the reads or writes of a
// transfer, summed.
type Request struct {
	// Request names it as the engine's operations do, such as open_write,
	// remove or readdir.
	Request string `json:"request"`
	Path    string `json:"path,omitempty"`
	Target  string `json:"target,omitempty"`

	// Count and Bytes are set for summed reads or writes.
	Count uint64 `json:"count,omitempty"`
	Bytes uint64 `json:"bytes,omitempty"`

	// Reply is ok, eof, or the status it failed with, such as
	// permission_denied, or connection_closed if no reply was sent.
	Reply    string        `json:"reply"`
	Outcome  string        `json:"outcome"`
	Fault    *Fault        `json:"fault,omitempty"`
	Duration events.Millis `json:"duration_ms,omitempty"`
}

// Lines returns the lines that evs, a run's events oldest first, make, in
// the order they began. names gives faults' names by their rule IDs; a rule
// without one is named by its ID.
func Lines(evs []events.Event, names map[string]string) []Line {
	b := &builder{
		names:     names,
		conns:     make(map[uint64]*conn),
		open:      make(map[openKey]*Line),
		closing:   make(map[openKey]*Line),
		pending:   make(map[requestKey]events.Event),
		downloads: make(map[string]*Line),
	}
	for _, e := range evs {
		b.add(e)
	}
	for _, l := range b.open {
		l.InProgress = true
	}
	lines := make([]Line, len(b.lines))
	for i, l := range b.lines {
		lines[i] = *l
	}
	return lines
}

type builder struct {
	names map[string]string
	lines []*Line
	conns map[uint64]*conn
	// open are the transfers and listings whose handles are open, and
	// closing the transfers whose totals are in, which their closes are
	// still to join.
	open    map[openKey]*Line
	closing map[openKey]*Line
	// pending are faults on requests whose replies have not been sent.
	pending   map[requestKey]events.Event
	downloads map[string]*Line
}

// conn is what is known of a connection.
type conn struct {
	remote string
	line   *Line
	// fault is one that ended the connection before its login.
	fault *events.Event
}

type openKey struct {
	conn    uint64
	path    string
	listing bool
}

type requestKey struct {
	conn uint64
	id   uint32
}

func (b *builder) add(e events.Event) {
	switch e.Kind {
	case events.Connected:
		b.conns[e.Connection] = &conn{remote: e.Remote}
	case events.Authenticated:
		c := b.connection(e.Connection)
		c.line = b.newLine(e, "connected")
		c.line.Remote, c.line.Client = c.remote, e.Client
	case events.Disconnected:
		b.disconnected(e)
	case events.FaultInjected:
		b.fault(e)
	case events.Operation:
		b.operation(e)
	case events.Transfer:
		b.transfer(e)
	}
}

func (b *builder) connection(id uint64) *conn {
	c, ok := b.conns[id]
	if !ok {
		c = &conn{}
		b.conns[id] = c
	}
	return c
}

func (b *builder) newLine(e events.Event, kind string) *Line {
	l := &Line{ID: e.ID, Time: e.Time, Connection: e.Connection, User: e.User, Kind: kind, Path: e.Path, Target: e.Target, Outcome: OK, Requests: []Request{}}
	b.lines = append(b.lines, l)
	return l
}

func (b *builder) faultOf(e events.Event) *Fault {
	f := &Fault{ID: e.Rule, Name: e.Rule}
	if name, ok := b.names[e.Rule]; ok {
		f.Name = name
	}
	if e.Fault != nil {
		f.Type = e.Fault.Type
	}
	return f
}

func (b *builder) fault(e events.Event) {
	switch {
	case e.RequestID != nil:
		b.pending[requestKey{e.Connection, *e.RequestID}] = e
	case e.Connection == 0:
		kind := "fault"
		if e.Fault != nil && e.Fault.Type == events.ListenerDownFault {
			kind = "outage"
		}
		l := b.newLine(e, kind)
		l.Outcome, l.Fault = ByFault, b.faultOf(e)
	case e.Request == "connect" || e.Request == "authenticate":
		c := b.connection(e.Connection)
		if c.line == nil {
			c.fault = &e
			return
		}
		c.line.Outcome, c.line.Fault = ByFault, b.faultOf(e)
		c.line.Requests = append(c.line.Requests, Request{Request: e.Request, Reply: OK, Outcome: ByFault, Fault: c.line.Fault})
	default:
		// A fault at a moment acts on the connection, whatever it is doing.
		l := b.newLine(e, "fault")
		l.Outcome, l.Fault = ByFault, b.faultOf(e)
	}
}

func (b *builder) disconnected(e events.Event) {
	// Requests that a fault stopped before their replies were sent, in the
	// order the faults were injected.
	var stopped []events.Event
	for key, fault := range b.pending {
		if key.conn == e.Connection {
			delete(b.pending, key)
			stopped = append(stopped, fault)
		}
	}
	slices.SortFunc(stopped, func(a, b events.Event) int { return cmp.Compare(a.ID, b.ID) })
	for _, fault := range stopped {
		r := Request{Request: requestName(fault.Request, ""), Path: fault.Path, Target: fault.Target, Reply: ConnectionClosed, Outcome: ByFault, Fault: b.faultOf(fault)}
		if l := b.openFor(fault.Connection, fault.Path, r.Request); l != nil {
			l.addRequest(r)
			continue
		}
		if l := b.closing[openKey{fault.Connection, fault.Path, false}]; l != nil && (r.Request == "read" || r.Request == "write") {
			l.addRequest(r)
			continue
		}
		l := b.newLine(fault, kindOf(r.Request))
		l.addRequest(r)
	}
	for key := range b.open {
		if key.conn == e.Connection && key.listing {
			delete(b.open, key)
		}
	}
	for key := range b.closing {
		if key.conn == e.Connection {
			delete(b.closing, key)
		}
	}
	c := b.connection(e.Connection)
	delete(b.conns, e.Connection)
	if c.line == nil {
		l := b.newLine(e, "connection_failed")
		l.Remote = c.remote
		if c.fault != nil {
			l.Outcome, l.Fault = ByFault, b.faultOf(*c.fault)
		}
		return
	}
	l := b.newLine(e, "disconnected")
	l.Duration = events.Millis(e.Time.Sub(c.line.Time))
}

func (b *builder) operation(e events.Event) {
	name := requestName(e.Request, e.Mode)
	r := Request{Request: name, Path: e.Path, Target: e.Target, Reply: replyName(e.Reply), Outcome: OK, Duration: e.Duration}
	if e.RequestID != nil {
		key := requestKey{e.Connection, *e.RequestID}
		if fault, ok := b.pending[key]; ok {
			delete(b.pending, key)
			r.Outcome, r.Fault = ByFault, b.faultOf(fault)
		}
	}
	if r.Fault == nil && e.Rule != "" {
		r.Outcome, r.Fault = ByFault, b.faultOf(e)
	}
	if r.Outcome == OK && r.Reply != OK && r.Reply != "eof" {
		r.Outcome = Failed
	}

	switch name {
	case "open_read", "open_write":
		l := b.newLine(e, kindOf(name))
		l.addRequest(r)
		if e.Reply == "SSH_FXP_HANDLE" {
			key := openKey{e.Connection, e.Path, false}
			b.open[key] = l
			delete(b.closing, key)
		}
		l.ReadOnly = e.ReadOnly
		return
	case "opendir":
		l := b.newLine(e, "listing")
		l.addRequest(r)
		if e.Reply == "SSH_FXP_HANDLE" {
			b.open[openKey{e.Connection, e.Path, true}] = l
		}
		return
	case "readdir", "read", "write", "fstat", "fsetstat":
		if l := b.openFor(e.Connection, e.Path, name); l != nil {
			l.addRequest(r)
			return
		}
	case "close":
		if l := b.openFor(e.Connection, e.Path, name); l != nil {
			l.addRequest(r)
			if l.Kind == "listing" {
				delete(b.open, openKey{e.Connection, e.Path, true})
			}
			return
		}
		return
	case "realpath", "statvfs":
		// Clients ask these as a matter of course, so only a failure is
		// worth a line.
		if r.Outcome == OK {
			return
		}
	}
	l := b.newLine(e, kindOf(name))
	l.ReadOnly = e.ReadOnly
	l.addRequest(r)
}

// openFor returns the open transfer or listing of path on conn that a
// request named so belongs to, or nil.
func (b *builder) openFor(conn uint64, path, request string) *Line {
	listing := request == "readdir"
	if request == "close" {
		key := openKey{conn, path, false}
		if l := b.closing[key]; l != nil {
			delete(b.closing, key)
			return l
		}
		if l := b.open[key]; l != nil {
			return l
		}
		listing = true
	}
	return b.open[openKey{conn, path, listing}]
}

func (b *builder) transfer(e events.Event) {
	key := openKey{e.Connection, e.Path, false}
	t := e.Transfer
	l := b.open[key]
	delete(b.open, key)
	// The transfer's line takes the reply to the client's CLOSE, or the
	// requests that a fault stopped as it ended the connection, which the
	// connection's end reports.
	if l != nil && t != nil {
		b.closing[key] = l
	}
	if l == nil {
		l = b.newLine(e, "open")
	}
	if t == nil {
		return
	}
	if t.Writes > 0 {
		l.addRequest(Request{Request: "write", Path: e.Path, Count: t.Writes, Bytes: t.BytesWritten, Reply: OK, Outcome: OK})
	}
	if t.Reads > 0 {
		l.addRequest(Request{Request: "read", Path: e.Path, Count: t.Reads, Bytes: t.BytesRead, Reply: OK, Outcome: OK})
	}
	switch {
	case t.BytesWritten > 0 || (t.Mode == "write" && t.BytesRead == 0):
		l.Kind, l.Bytes = "upload", t.BytesWritten
	case t.BytesRead > 0 || t.Mode == "read":
		l.Kind, l.Bytes = "download", t.BytesRead
	default:
		l.Kind = "open"
	}
	l.Duration = events.Millis(e.Time.Sub(l.Time))
	if e.Rule != "" && l.Fault == nil {
		l.Outcome, l.Fault = ByFault, b.faultOf(e)
	}
	if t.Closed == events.ClosedBySession && l.Outcome == OK {
		l.Outcome, l.Reason = Failed, ConnectionClosed
	}
	if l.Kind == "download" {
		who := l.User + "\x00" + l.Path
		if first, ok := b.downloads[who]; ok {
			l.Repeat = &Repeat{ID: first.ID, Time: first.Time}
		} else {
			b.downloads[who] = l
		}
	}
}

// addRequest adds r to l, which takes the outcome of its worst request: a
// fault's over a failure's.
func (l *Line) addRequest(r Request) {
	l.Requests = append(l.Requests, r)
	switch {
	case r.Outcome == ByFault && l.Outcome != ByFault:
		l.Outcome, l.Fault, l.Reason = ByFault, r.Fault, r.Reply
	case r.Outcome == Failed && l.Outcome == OK:
		l.Outcome, l.Reason = Failed, r.Reply
	}
	if l.Reason == OK {
		l.Reason = ""
	}
}

// requestName names an event's request as the engine's operations do, an
// open by how it asked for its file.
func requestName(request, mode string) string {
	switch request {
	case "SSH_FXP_OPEN":
		if mode == "read" {
			return "open_read"
		}
		return "open_write"
	case "posix-rename@openssh.com":
		return "rename"
	case "statvfs@openssh.com":
		return "statvfs"
	case "connect", "authenticate":
		return request
	}
	return strings.ToLower(strings.TrimPrefix(request, "SSH_FXP_"))
}

// kindOf returns the kind of line that a request named so begins.
func kindOf(request string) string {
	switch request {
	case "open_read":
		return "download"
	case "open_write":
		return "upload"
	case "opendir", "readdir":
		return "listing"
	case "stat", "lstat", "fstat":
		return "check"
	case "remove":
		return "delete"
	case "rename", "mkdir", "rmdir", "setstat", "realpath", "statvfs":
		return request
	case "fsetstat":
		return "setstat"
	}
	return "other"
}

// replyName names a reply as ok, eof or the status it failed with.
func replyName(reply string) string {
	switch {
	case reply == "", reply == "SSH_FX_OK", strings.HasPrefix(reply, "SSH_FXP_"):
		return OK
	case strings.HasPrefix(reply, "SSH_FX_"):
		return strings.ToLower(strings.TrimPrefix(reply, "SSH_FX_"))
	}
	return reply
}
