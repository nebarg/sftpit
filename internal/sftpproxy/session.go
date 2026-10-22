// Package sftpproxy relays SFTP sessions between a client and a backend
// server, decoding every packet in both directions. The proxy negotiates with
// each side separately, owns the request IDs on the backend, resolves every
// client path against the backend's default directory and tracks which path
// each open handle refers to, so every request can be attributed to a file.
// It can inject a fault into any request it forwards: delay, stall or fail
// the request, or drop or freeze the connection or end the session, before
// or after the backend acts, or at a moment whatever the client is doing. It can also cut off an upload at a byte offset, corrupt what a
// download reads, misreport sizes, and snapshot the file that a faulted
// handle leaves behind before anything else can change it.
package sftpproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"path"
	"slices"
	"sync"
	"time"

	"github.com/nebarg/sftpit/internal/sftpwire"
)

const (
	// maxPacketLength is the limit OpenSSH's sftp-server and sftp client
	// both apply.
	maxPacketLength = 256 * 1024

	// maxQueuedReplies bounds the replies a session holds for the client.
	// A client with more requests outstanding waits, as it would for a busy
	// server.
	maxQueuedReplies = 256
)

// supportedExtensions are the extensions the proxy implements, with the
// versions OpenSSH advertises. A session offers the client each one only if
// the backend advertises the same version.
var supportedExtensions = []sftpwire.Extension{
	{Name: sftpwire.ExtPosixRename, Data: "1"},
	{Name: sftpwire.ExtStatVFS, Data: "2"},
}

var (
	errBackendClosed = errors.New("sftpproxy: backend closed the session")
	errStopped       = errors.New("sftpproxy: session stopped")
	errDropped       = errors.New("sftpproxy: connection dropped by a fault")
	errEnded         = errors.New("sftpproxy: session ended by a fault")
)

// Options configures a session.
type Options struct {
	// Faults chooses the fault, if any, for each request the proxy would
	// forward, and for each entry of a READDIR reply. It is called once per
	// request, in request order, and once per entry as each READDIR reply
	// arrives, so it must be safe for concurrent use. It must not block. A
	// nil Faults, or a nil Action, lets requests through unchanged. It is
	// not called for a write that reaches a PartialUpload's cutoff, or a read
	// that a CorruptDownload changes, which decide those requests
	// themselves.
	Faults func(Request) Action

	// Timers are the faults for moments in the session, rather than for
	// requests. A Timer whose moment has passed fires as the session starts.
	Timers []Timer

	// Conn is the client's connection, which Drop and Freeze act on. It is
	// required if Faults or Timers can give either.
	Conn Conn

	// ReplyOrder is the order in which replies reach the client. The zero
	// value is RequestOrder.
	ReplyOrder ReplyOrder

	// Snapshot describes the file that a faulted file handle leaves behind,
	// which the session logs as evidence that a later request, such as a
	// retry that truncates the file, cannot destroy. A file handle is
	// faulted once a fault acts on the OPEN that returned it or on a request
	// through it, including a write that reaches a PartialUpload's cutoff.
	// Choosing a PartialUpload or CorruptDownload for the OPEN does not
	// count, and neither a CorruptDownload nor a WrongSize ever faults a
	// handle, since neither changes a file.
	//
	// The session calls Snapshot with the handle's path once nothing more
	// can be written through the handle: when the backend has answered the
	// handle's CLOSE, before the client gets that reply; when a Drop or
	// Freeze ends the session, before the connection is closed or frozen;
	// or else once the session has closed the backend stream. No later
	// request on the file reaches the backend until it returns. It is
	// called once per faulted handle. A nil Snapshot records nothing.
	Snapshot func(path string) (Snapshot, error)

	// Logger receives injected faults, snapshots and, at debug level, every
	// request. Nil means slog.Default().
	Logger *slog.Logger
}

// Conn is the connection a client's session runs over.
type Conn interface {
	// Close closes the connection normally.
	Close() error

	// Reset aborts the connection so the client sees a TCP reset.
	Reset() error

	// Freeze stops all traffic on the connection until it is closed.
	Freeze()
}

// Serve relays one SFTP session from client to backend until either side
// ends it, a fault drops the connection or ends the session, or ctx is
// cancelled, and closes both before returning. It returns nil when the
// client ends the session or a Drop, Freeze or EndSession ends it, or
// ctx.Err() if ctx is cancelled first. Every fault wait has ended by the time Serve returns, so no request
// reaches the backend afterwards.
//
// Replies reach the client in the order opts.ReplyOrder sets. A malformed
// client request ends the session, as it does in OpenSSH's sftp-server, and
// so does a backend reply that does not fit its request.
func Serve(ctx context.Context, client, backend io.ReadWriteCloser, opts Options) error {
	s := &session{
		client:    client,
		clientIn:  bufio.NewReader(client),
		backend:   backend,
		backendIn: bufio.NewReader(backend),
		faults:    opts.Faults,
		conn:      opts.Conn,
		order:     opts.ReplyOrder,
		snapshot:  opts.Snapshot,
		logger:    opts.Logger,
		replies:   make(chan slot, maxQueuedReplies),
		moments:   make(chan *request),
		done:      make(chan struct{}),
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	if s.order == CompletionOrder {
		s.completion = completionState{
			inFlight: make(chan struct{}, maxQueuedReplies),
			waiting:  make(map[string]*request),
		}
	}
	stopWhenCancelled := context.AfterFunc(ctx, func() { s.stop(ctx.Err()) })
	defer stopWhenCancelled()

	if err := s.start(); err != nil {
		s.stop(err)
		return s.result()
	}
	for _, t := range opts.Timers {
		if err := s.checkMoment(t.Action); err != nil {
			s.stop(err)
			return s.result()
		}
		s.wg.Go(func() { s.at(time.Until(t.At), nil, &request{action: t.Action}, t.Reserve) })
	}
	s.wg.Go(func() { s.stop(s.relayReplies()) })
	s.wg.Go(func() { s.stop(s.writeReplies()) })
	s.stop(s.relayRequests())
	s.wg.Wait()
	s.snapshotRest(closedBySessionEnd)
	return s.result()
}

type session struct {
	client    io.ReadWriteCloser
	clientIn  *bufio.Reader
	backend   io.ReadWriteCloser
	backendIn *bufio.Reader
	faults    func(Request) Action
	conn      Conn
	order     ReplyOrder
	snapshot  func(string) (Snapshot, error)
	logger    *slog.Logger
	tracker   *tracker

	// wg tracks every goroutine of the session, including those holding
	// requests and replies for a fault.
	wg sync.WaitGroup

	// sendMu keeps requests to the backend whole and in the order they pass
	// the halted check, when several goroutines forward them.
	sendMu sync.Mutex

	mu sync.Mutex
	// halted stops requests reaching the backend once a drop is under way.
	halted bool
	// fired stops replies reaching the client once a fault for a moment
	// has fired.
	fired bool
	// unanswered counts the requests the backend has yet to answer.
	unanswered int
	// completion is used only in completion order.
	completion completionState

	// version is the VERSION packet sent to the client, sent again if the
	// client repeats INIT, as OpenSSH and pkg/sftp both do.
	version []byte

	replies chan slot
	// moments carries a fault for a moment, once the backend has answered
	// every request it was sent, to the goroutine writing replies.
	moments chan *request
	// drained is closed once the backend has answered every request it was
	// sent, after forwarding has stopped.
	drained chan struct{}

	done     chan struct{}
	stopOnce sync.Once
	err      error
}

// stop ends the session for the first reason given and closes both streams,
// which unblocks every goroutine reading or writing them.
func (s *session) stop(err error) {
	s.stopOnce.Do(func() {
		s.err = err
		close(s.done)
		s.client.Close()
		s.backend.Close()
	})
}

func (s *session) result() error {
	if errors.Is(s.err, io.EOF) || errors.Is(s.err, errDropped) || errors.Is(s.err, errEnded) {
		return nil
	}
	return s.err
}

// start negotiates with the backend, learns its default directory and then
// answers the client's INIT.
func (s *session) start() error {
	exts, err := s.initBackend()
	if err != nil {
		return err
	}
	dir, err := s.backendDirectory()
	if err != nil {
		return err
	}
	s.tracker = newTracker(dir, exts)

	b, err := sftpwire.ReadPacket(s.clientIn, maxPacketLength)
	if err != nil {
		return err
	}
	if _, err := sftpwire.DecodeInit(b); err != nil {
		return err
	}
	s.version = sftpwire.AppendVersion(nil, sftpwire.Version{Version: 3, Extensions: exts})
	if _, err := s.client.Write(s.version); err != nil {
		return fmt.Errorf("sftpproxy: write VERSION: %w", err)
	}
	return nil
}

// initBackend negotiates version 3 with the backend and returns the
// supported extensions it also advertises.
func (s *session) initBackend() ([]sftpwire.Extension, error) {
	if _, err := s.backend.Write(sftpwire.AppendInit(nil, sftpwire.Init{Version: 3})); err != nil {
		return nil, fmt.Errorf("sftpproxy: write backend INIT: %w", err)
	}
	b, err := s.readBackend()
	if err != nil {
		return nil, err
	}
	v, err := sftpwire.DecodeVersion(b)
	if err != nil {
		return nil, err
	}
	if v.Version != 3 {
		return nil, fmt.Errorf("sftpproxy: backend speaks SFTP version %d, want 3", v.Version)
	}
	var exts []sftpwire.Extension
	for _, ext := range supportedExtensions {
		if slices.Contains(v.Extensions, ext) {
			exts = append(exts, ext)
		}
	}
	return exts, nil
}

// backendDirectory asks the backend for its default directory, against
// which the client's relative paths are resolved.
func (s *session) backendDirectory() (string, error) {
	const id = 0
	if _, err := s.backend.Write(sftpwire.AppendPacket(nil, id, &sftpwire.RealPath{Path: "."})); err != nil {
		return "", fmt.Errorf("sftpproxy: write backend REALPATH: %w", err)
	}
	b, err := s.readBackend()
	if err != nil {
		return "", err
	}
	replyID, reply, err := sftpwire.DecodeReply(b)
	if err != nil {
		return "", err
	}
	if name, ok := reply.(*sftpwire.NameReply); ok && replyID == id && len(name.Entries) == 1 {
		if dir := name.Entries[0].Filename; path.IsAbs(dir) {
			return path.Clean(dir), nil
		}
	}
	if st, ok := reply.(*sftpwire.StatusReply); ok {
		return "", fmt.Errorf("sftpproxy: backend REALPATH %q failed: %v %s", ".", st.Code, st.Message)
	}
	return "", fmt.Errorf("sftpproxy: backend REALPATH %q gave no absolute path", ".")
}

func (s *session) readBackend() ([]byte, error) {
	b, err := sftpwire.ReadPacket(s.backendIn, maxPacketLength)
	if errors.Is(err, io.EOF) {
		return nil, errBackendClosed
	}
	if err != nil {
		return nil, fmt.Errorf("sftpproxy: read backend: %w", err)
	}
	return b, nil
}

// relayRequests forwards client requests to the backend until the client
// ends the session or a drop stops forwarding.
func (s *session) relayRequests() error {
	for !s.isHalted() {
		b, err := sftpwire.ReadPacket(s.clientIn, maxPacketLength)
		if err != nil {
			if s.isHalted() {
				// The drop closed the connection under the read.
				break
			}
			return err
		}
		if err := s.handleRequest(b); err != nil {
			return err
		}
	}
	<-s.done
	return errStopped
}

func (s *session) handleRequest(b []byte) error {
	if s.order == CompletionOrder {
		select {
		case s.completion.inFlight <- struct{}{}:
		case <-s.done:
			return errStopped
		}
	}
	if sftpwire.PacketType(b[0]) == sftpwire.TypeInit {
		if _, err := sftpwire.DecodeInit(b); err != nil {
			return err
		}
		return s.replyNow(s.version)
	}

	clientID, p, err := sftpwire.DecodeRequest(b)
	if unsupported, ok := errors.AsType[*sftpwire.UnsupportedError](err); ok {
		s.logger.Info("rejected unsupported sftp request", "err", unsupported)
		return s.replyNow(sftpwire.AppendPacket(nil, unsupported.ID, status(sftpwire.StatusOpUnsupported)))
	}
	if err != nil {
		return err
	}

	req, rejection := s.tracker.describe(clientID, p)
	if rejection != nil {
		s.logRequest(req, rejection)
		return s.replyNow(sftpwire.AppendPacket(nil, clientID, rejection))
	}
	if err := s.decide(req); err != nil {
		return err
	}
	if req.eof {
		eof := status(sftpwire.StatusEOF)
		s.logRequest(req, eof)
		return s.replyNow(sftpwire.AppendPacket(nil, clientID, eof))
	}
	s.prepareSnapshot(req)
	req.reply = make(slot, 1)
	if s.order == CompletionOrder {
		return s.schedule(req)
	}
	if err := s.enqueue(req.reply); err != nil {
		return err
	}
	return s.process(req)
}

// decide chooses req's fault: the cutoff's, if req is a write that reaches
// the cutoff on its handle, the corruption's, if req is a read that the
// corruption on its handle changes, or else whatever Faults chooses.
func (s *session) decide(req *request) error {
	if s.faults == nil {
		return nil
	}
	if !s.cut(req) && !s.corrupt(req) {
		req.action = s.faults(Request{Packet: req.packet, Path: req.path, Target: req.target})
		if err := s.checkFault(req.packet, req.action); err != nil {
			return err
		}
		switch a := req.action.(type) {
		case PartialUpload:
			req.action, req.upload = nil, &upload{PartialUpload: a}
		case CorruptDownload:
			req.action, req.download = nil, &download{CorruptDownload: a}
		case Timed:
			req.action, req.timed = nil, &a
		case WrongSize:
			req.action, req.wrongSize = nil, &a
		}
	}
	if req.action != nil {
		s.tracker.fault(req)
	}
	return nil
}

// checkFault reports an action that the session cannot apply to p.
func (s *session) checkFault(p sftpwire.Packet, a Action) error {
	switch a := a.(type) {
	case Drop, Freeze:
		if s.conn == nil {
			return fmt.Errorf("sftpproxy: a %T fault needs Options.Conn", a)
		}
	case PartialUpload:
		if _, ok := p.(*sftpwire.Open); !ok {
			return fmt.Errorf("sftpproxy: a PartialUpload fault is for OPEN, not %v", operation(p))
		}
		switch a.Result.(type) {
		case Fail, Drop, Freeze:
			return s.checkFault(p, a.Result)
		}
		return fmt.Errorf("sftpproxy: a PartialUpload result must be a Fail, Drop or Freeze, not %T", a.Result)
	case Timed:
		if _, ok := p.(*sftpwire.Open); !ok {
			return fmt.Errorf("sftpproxy: a Timed fault is for OPEN, not %v", operation(p))
		}
		return s.checkMoment(a.Action)
	case CorruptDownload:
		if _, ok := p.(*sftpwire.Open); !ok {
			return fmt.Errorf("sftpproxy: a CorruptDownload fault is for OPEN, not %v", operation(p))
		}
		switch a.Corruption {
		case Truncate:
		case OmitRange, FlipBytes:
			if a.Length == 0 || a.Length > math.MaxUint64-a.Offset {
				return fmt.Errorf("sftpproxy: a CorruptDownload %v of %d bytes at %d does not fit a file", a.Corruption, a.Length, a.Offset)
			}
		default:
			return fmt.Errorf("sftpproxy: unknown CorruptDownload corruption %v", a.Corruption)
		}
	case WrongSize:
		switch p.(type) {
		case *sftpwire.Stat, *sftpwire.LStat, *sftpwire.FStat:
		default:
			return fmt.Errorf("sftpproxy: a WrongSize fault is for STAT, LSTAT, FSTAT or a READDIR entry, not %v", operation(p))
		}
	}
	return nil
}

// checkMoment reports an action that the session cannot take at a moment.
func (s *session) checkMoment(a Action) error {
	switch a.(type) {
	case Drop, Freeze:
		if s.conn == nil {
			return fmt.Errorf("sftpproxy: a %T fault needs Options.Conn", a)
		}
	case EndSession:
	default:
		return fmt.Errorf("sftpproxy: a fault at a moment must be a Drop, Freeze or EndSession, not %T", a)
	}
	return nil
}

// process applies req's fault if that acts before the backend, then
// forwards req unless the fault answered it or a drop has stopped
// forwarding, and waits for any snapshot it needs. In request order it runs
// on the request goroutine, so a held request holds back every later one.
func (s *session) process(req *request) error {
	if s.isHalted() {
		return nil
	}
	if req.action != nil && req.action.when() == Before {
		s.logFault(req)
		switch a := req.action.(type) {
		case Delay:
			if err := s.hold(req, a.Duration, nil); err != nil {
				return err
			}
		case Stall:
			if err := s.hold(req, a.Limit, a.Release); err != nil {
				return err
			}
		case Fail:
			s.answer(req.reply, outcome{packet: sftpwire.AppendPacket(nil, req.clientID, status(a.Status))})
			return nil
		case Drop, Freeze, EndSession:
			s.stopForwarding()
			s.placeDrop(req)
			return nil
		}
	}
	if err := s.send(req); err != nil {
		return err
	}
	return s.awaitSnapshot(req)
}

// send forwards req to the backend, as two reads if it is a split READ,
// unless a drop has stopped forwarding. Nothing reaches the backend after a
// request whose drop comes after it.
func (s *session) send(req *request) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	s.mu.Lock()
	if s.halted {
		s.mu.Unlock()
		return nil
	}
	s.unanswered++
	if req.split != nil {
		s.unanswered++
	}
	switch req.action.(type) {
	case Drop, Freeze, EndSession:
		s.halted = true
	}
	s.mu.Unlock()

	s.tracker.register(req)
	b := sftpwire.AppendPacket(nil, req.proxyID, req.packet)
	if req.split != nil {
		b = sftpwire.AppendPacket(b, req.split.rest.proxyID, req.split.rest.packet)
	}
	if _, err := s.backend.Write(b); err != nil {
		return fmt.Errorf("sftpproxy: write backend request: %w", err)
	}
	return nil
}

func (s *session) stopForwarding() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.halted = true
}

func (s *session) isHalted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.halted
}

// placeDrop puts req's drop in the reply stream. In request order its slot
// already has its place, behind every earlier reply. In completion order it
// goes in once the backend has answered every request it has, behind the
// replies ready by then; replies still held by a fault are lost with the
// connection.
func (s *session) placeDrop(req *request) {
	if s.order == RequestOrder {
		s.answer(req.reply, outcome{drop: req})
		return
	}
	s.mu.Lock()
	if s.completion.dropping {
		s.mu.Unlock()
		return
	}
	s.completion.dropping = true
	if s.unanswered > 0 {
		s.completion.pendingDrop = req
		req = nil
	}
	s.mu.Unlock()
	if req != nil {
		s.answer(req.reply, outcome{drop: req})
	}
}

// answered records that the backend's reply to a request has been
// delivered, and places a drop that was waiting for the backend to finish.
func (s *session) answered() {
	s.mu.Lock()
	s.unanswered--
	var drop *request
	if s.unanswered == 0 {
		drop, s.completion.pendingDrop = s.completion.pendingDrop, nil
		if s.drained != nil {
			close(s.drained)
			s.drained = nil
		}
	}
	s.mu.Unlock()
	if drop != nil {
		s.answer(drop.reply, outcome{drop: drop})
	}
}

// at takes m's action, a fault for a moment, once after passes, unless
// closing is closed or the session ends first.
func (s *session) at(after time.Duration, closing <-chan struct{}, m *request, reserve func() bool) {
	timer := time.NewTimer(after)
	defer timer.Stop()
	select {
	case <-timer.C:
		s.fire(m, reserve)
	case <-closing:
	case <-s.done:
	}
}

// fire takes m's action, unless reserve declines it. Nothing more reaches
// the backend, and once the backend has answered every request it was sent,
// the session ends as the action says, whatever replies are still to be
// written: a connection that fails at a moment loses them.
func (s *session) fire(m *request, reserve func() bool) {
	if reserve != nil && !reserve() {
		return
	}
	s.tracker.fault(m)
	s.logFault(m)
	s.mu.Lock()
	s.halted, s.fired = true, true
	drained := s.drained
	if s.unanswered > 0 && drained == nil {
		drained = make(chan struct{})
		s.drained = drained
	}
	s.mu.Unlock()
	if drained != nil {
		select {
		case <-drained:
		case <-s.done:
			return
		}
	}
	select {
	case s.moments <- m:
	case <-s.done:
	}
}

// hold waits until limit passes or release is closed. It returns errStopped
// if the session ends first.
func (s *session) hold(req *request, limit time.Duration, release <-chan struct{}) error {
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case <-timer.C:
		if release != nil {
			s.logger.Info("fault ended at its limit", s.faultAttrs(req)...)
		}
		return nil
	case <-release:
		s.logger.Info("fault released", s.faultAttrs(req)...)
		return nil
	case <-s.done:
		return errStopped
	}
}

// enqueue reserves the client's next reply position for reply.
func (s *session) enqueue(reply slot) error {
	select {
	case s.replies <- reply:
		return nil
	case <-s.done:
		return errStopped
	}
}

// replyNow answers a request with a reply the proxy already has.
func (s *session) replyNow(packet []byte) error {
	reply := make(slot, 1)
	if s.order == RequestOrder {
		if err := s.enqueue(reply); err != nil {
			return err
		}
	}
	s.answer(reply, outcome{packet: packet})
	return nil
}

// answer settles the outcome in a request's slot. In request order the slot
// already has its place in the queue; in completion order it joins the
// queue now, which never blocks, because inFlight bounds the slots that can
// be waiting.
func (s *session) answer(reply slot, out outcome) {
	reply <- out
	if s.order == CompletionOrder {
		s.replies <- reply
	}
}

// relayReplies hands each backend reply to the slot of its request, with
// any corruption or wrong sizes applied, re-encoded with the client's
// request ID.
func (s *session) relayReplies() error {
	for {
		b, err := s.readBackend()
		if err != nil {
			return err
		}
		proxyID, p, err := sftpwire.DecodeReply(b)
		if err != nil {
			return fmt.Errorf("sftpproxy: backend reply: %w", err)
		}
		req, err := s.tracker.complete(proxyID, p)
		if err != nil {
			return err
		}
		if h, ok := p.(*sftpwire.HandleReply); ok && req.timed != nil {
			s.armTimed(req, h.Handle)
		}
		s.logRequest(req, p)
		if req, p = joinReads(req, p); req != nil {
			flipBytes(req, p)
			if err := s.misreport(req, p); err != nil {
				return err
			}
			s.snapshotClosed(req)
			s.deliver(req, sftpwire.AppendPacket(nil, req.clientID, p))
		}
		s.answered()
	}
}

// deliver passes the backend's reply to req on to the client, applying req's
// fault if that acts after the backend. It never waits, so the backend's
// later replies keep flowing.
func (s *session) deliver(req *request, packet []byte) {
	if req.action == nil || req.action.when() != After {
		s.answer(req.reply, outcome{packet: packet})
		return
	}
	s.logFault(req)
	switch a := req.action.(type) {
	case Delay:
		s.wg.Go(func() { s.holdReply(req, a.Duration, nil, packet) })
	case Stall:
		s.wg.Go(func() { s.holdReply(req, a.Limit, a.Release, packet) })
	case Fail:
		s.answer(req.reply, outcome{packet: sftpwire.AppendPacket(nil, req.clientID, status(a.Status))})
	case Drop, Freeze, EndSession:
		s.placeDrop(req)
	}
}

// armTimed starts the clock of req's Timed on the handle id that req opened.
// Closing the handle stops it.
func (s *session) armTimed(req *request, id string) {
	h, closing := s.tracker.watchClose(id)
	m := &request{action: req.timed.Action, path: req.path, handle: h}
	s.wg.Go(func() { s.at(req.timed.After, closing, m, req.timed.Reserve) })
}

func (s *session) holdReply(req *request, limit time.Duration, release <-chan struct{}, packet []byte) {
	if s.hold(req, limit, release) == nil {
		s.answer(req.reply, outcome{packet: packet})
	}
}

// writeReplies writes replies to the client in the order of the queue:
// request order, or the order replies become ready in completion order.
func (s *session) writeReplies() error {
	for {
		var next slot
		select {
		case next = <-s.replies:
		case m := <-s.moments:
			return s.drop(m)
		case <-s.done:
			return errStopped
		}
		select {
		case m := <-s.moments:
			return s.drop(m)
		case out := <-next:
			if out.drop != nil {
				return s.drop(out.drop)
			}
			if s.hasFired() {
				return s.awaitMoment()
			}
			if _, err := s.client.Write(out.packet); err != nil {
				return fmt.Errorf("sftpproxy: write reply: %w", err)
			}
			if s.order == CompletionOrder {
				<-s.completion.inFlight
			}
		case <-s.done:
			return errStopped
		}
	}
}

func (s *session) hasFired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fired
}

// awaitMoment ends the session at the fault for a moment that has fired,
// once the backend has answered what it was sent.
func (s *session) awaitMoment() error {
	select {
	case m := <-s.moments:
		return s.drop(m)
	case <-s.done:
		return errStopped
	}
}

// drop ends the session at req's Drop, Freeze or EndSession. A Drop or
// Freeze acts on the connection, so the client sees it fail rather than the
// session close in an orderly way. The backend has answered every request it
// was sent, so the files of the faulted handles still open are snapshotted
// first: a client that reconnects to retry must not change them before then.
func (s *session) drop(req *request) error {
	s.snapshotRest(closedByFault)
	var err error
	switch a := req.action.(type) {
	case EndSession:
		return errEnded
	case Drop:
		if a.Reset {
			err = s.conn.Reset()
		} else {
			err = s.conn.Close()
		}
	case Freeze:
		s.conn.Freeze()
		if holdErr := s.hold(req, a.Limit, a.Release); holdErr != nil {
			// Whatever ended the session decides its result. A frozen
			// connection must still not outlive it.
			s.conn.Close()
			return holdErr
		}
		err = s.conn.Close()
	}
	if err != nil {
		return fmt.Errorf("sftpproxy: drop connection: %w", err)
	}
	return errDropped
}

func (s *session) logFault(req *request) {
	if req.cut {
		// cut logged it when it decided the request.
		return
	}
	s.logger.Info("injected fault", s.faultAttrs(req)...)
}

// faultAttrs describes req's fault. A fault for a moment has no request, and
// a path only if it is a transfer's.
func (s *session) faultAttrs(req *request) []any {
	var attrs []any
	var when any = "timer"
	if req.packet != nil {
		attrs = append(attrs, "request", operation(req.packet))
		when = req.action.when()
	}
	if req.packet != nil || req.path != "" {
		attrs = append(attrs, "path", req.path)
	}
	if req.target != "" {
		attrs = append(attrs, "target", req.target)
	}
	switch a := req.action.(type) {
	case Delay:
		attrs = append(attrs, "fault", "delay", "when", when, "duration", a.Duration)
	case Stall:
		attrs = append(attrs, "fault", "stall", "when", when, "limit", a.Limit)
	case Fail:
		attrs = append(attrs, "fault", "fail", "when", when, "status", a.Status)
	case Drop:
		mode := "fin"
		if a.Reset {
			mode = "rst"
		}
		attrs = append(attrs, "fault", "close_connection", "when", when, "mode", mode)
	case Freeze:
		attrs = append(attrs, "fault", "freeze_connection", "when", when, "limit", a.Limit)
	case EndSession:
		attrs = append(attrs, "fault", "close_subsystem", "when", when)
	}
	if req.cut {
		attrs = append(attrs, "cutoff", req.upload.Cutoff, "offset", req.packet.(*sftpwire.Write).Offset)
	}
	return attrs
}

func (s *session) logRequest(req *request, reply sftpwire.Packet) {
	if !s.logger.Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	result := reply.Type().String()
	if st, ok := reply.(*sftpwire.StatusReply); ok {
		result = st.Code.String()
	}
	attrs := []any{"request", operation(req.packet), "path", req.path}
	if req.target != "" {
		attrs = append(attrs, "target", req.target)
	}
	attrs = append(attrs, "result", result)
	s.logger.Debug("sftp request", attrs...)
}
