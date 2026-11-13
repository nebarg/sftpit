package sftpproxy

import (
	"context"
	"log/slog"
	"time"

	"github.com/nebarg/sftpit/internal/events"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

// injection is a fault acting on a request, as the session logs and
// records it: the request, its paths and the fault.
type injection struct {
	request, path, target string
	fault                 Description
}

// attrs returns in as the attributes of a log record. A fault for a moment
// has no request, and a path only if it is a transfer's.
func (in injection) attrs() []any {
	var attrs []any
	if in.request != "" {
		attrs = append(attrs, "request", in.request)
	}
	if in.request != "" || in.path != "" {
		attrs = append(attrs, "path", in.path)
	}
	if in.target != "" {
		attrs = append(attrs, "target", in.target)
	}
	return append(attrs, in.fault.Attrs()...)
}

// injected records that the fault in describes acts on req. It logs the
// fault at level, and at info level, where a fault takes effect rather than
// carries on, records it as an event naming req's rule.
func (s *session) injected(req *request, level slog.Level, in injection) {
	req.injected = true
	// Taken before the fault is announced, so that a release that follows
	// the announcement ends it.
	switch req.action.(type) {
	case Stall, Freeze:
		if s.released != nil {
			req.released = s.released()
		}
	}
	s.logger.Log(context.Background(), level, "injected fault", in.attrs()...)
	if level < slog.LevelInfo || s.record == nil {
		return
	}
	e := events.Event{Kind: events.FaultInjected, Request: in.request, Path: in.path, Target: in.target, Rule: req.rule, Fault: in.fault.Fault()}
	if req.packet != nil {
		e.RequestID = new(req.clientID)
	}
	if waits(req.action) {
		s.mu.Lock()
		s.waits[req] = struct{}{}
		s.mu.Unlock()
	}
	s.record(e)
}

// waits reports whether a holds a request, a reply or the connection, until
// a wait ends.
func waits(a Action) bool {
	switch a.(type) {
	case Delay, Stall, Freeze:
		return true
	}
	return false
}

// ended records that the wait of req's fault has ended, for reason, unless
// its end has been recorded already.
func (s *session) ended(req *request, reason events.Reason) {
	s.mu.Lock()
	_, waiting := s.waits[req]
	delete(s.waits, req)
	s.mu.Unlock()
	if !waiting || s.record == nil {
		return
	}
	e := events.Event{Kind: events.FaultEnded, Rule: req.rule, Path: req.path, Reason: reason, Fault: &events.Fault{Type: FaultType(req.action)}}
	if req.packet != nil {
		e.Request, e.RequestID = operation(req.packet), new(req.clientID)
	}
	s.record(e)
}

// endWaits records the end of every wait still in progress as the session
// ends.
func (s *session) endWaits() {
	s.mu.Lock()
	var reqs []*request
	for req := range s.waits {
		reqs = append(reqs, req)
	}
	s.mu.Unlock()
	for _, req := range reqs {
		s.ended(req, events.SessionEnded)
	}
}

// recordOperation records req as an event as its reply is written.
// A read or write that succeeded and that no fault acted on is summed into
// its handle's transfer instead.
func (s *session) recordOperation(req *request, reply sftpwire.Packet) {
	if s.record == nil {
		return
	}
	name := replyName(reply)
	switch req.packet.(type) {
	case *sftpwire.Read, *sftpwire.Write:
		if !req.injected && !isFailure(reply) {
			return
		}
	}
	e := events.Event{
		Kind:         events.Operation,
		Request:      operation(req.packet),
		RequestID:    new(req.clientID),
		Path:         req.path,
		Target:       req.target,
		Reply:        name,
		BackendReply: req.backendReply,
		Duration:     events.Millis(time.Since(req.received)),
		ReadOnly:     req.readOnly,
	}
	if open, ok := req.packet.(*sftpwire.Open); ok {
		e.Mode = mode(open.Flags)
	}
	if req.injected {
		e.Rule = req.rule
	}
	s.record(e)
}

// isFailure reports whether reply is a status other than success or end of
// file.
func isFailure(reply sftpwire.Packet) bool {
	st, ok := reply.(*sftpwire.StatusReply)
	return ok && st.Code != sftpwire.StatusOK && st.Code != sftpwire.StatusEOF
}

// replyName names a reply as events give it: its status, or its type.
func replyName(reply sftpwire.Packet) string {
	if st, ok := reply.(*sftpwire.StatusReply); ok {
		return st.Code.String()
	}
	return reply.Type().String()
}

// count adds what the backend read or stored for req, a READ or WRITE
// through a handle, to the handle's transfer.
func (s *session) count(req *request, reply sftpwire.Packet) {
	if req.handle == nil {
		return
	}
	s.tracker.mu.Lock()
	defer s.tracker.mu.Unlock()
	t := &req.handle.totals
	switch p := req.packet.(type) {
	case *sftpwire.Read:
		if data, ok := reply.(*sftpwire.DataReply); ok {
			t.Reads++
			t.BytesRead += uint64(len(data.Data))
			t.End = max(t.End, p.Offset+uint64(len(data.Data)))
		}
	case *sftpwire.Write:
		if st, ok := reply.(*sftpwire.StatusReply); ok && st.Code == sftpwire.StatusOK {
			t.Writes++
			t.BytesWritten += uint64(len(p.Data))
			t.End = max(t.End, p.Offset+uint64(len(p.Data)))
		}
	}
}

// recordTransfer records the totals of h, a file handle, closed as closed
// says.
func (s *session) recordTransfer(h *handle, closed events.Closed) {
	if h == nil || !h.file {
		return
	}
	s.tracker.mu.Lock()
	t := h.totals
	t.Closed, t.Faulted = closed, h.faulted
	rule := ""
	if h.faulted {
		rule = h.rule
	}
	s.tracker.mu.Unlock()
	attrs := []any{"path", h.path, "mode", t.Mode, "bytes_read", t.BytesRead, "bytes_written", t.BytesWritten, "duration", time.Since(h.opened).Round(time.Millisecond), "closed", closed}
	if rule != "" {
		attrs = append(attrs, "rule", rule)
	}
	s.logger.Info("transfer", attrs...)
	if s.record != nil {
		s.record(events.Event{Kind: events.Transfer, Path: h.path, Rule: rule, Transfer: &t})
	}
}
