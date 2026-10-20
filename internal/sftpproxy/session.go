// Package sftpproxy relays SFTP sessions between a client and a backend
// server, decoding every packet in both directions. The proxy negotiates with
// each side separately, owns the request IDs on the backend, resolves every
// client path against the backend's default directory and tracks which path
// each open handle refers to, so every request can be attributed to a file.
// It can inject a fault into any request it forwards: delay, stall or fail
// the request, or drop or freeze the connection, before or after the backend
// acts.
package sftpproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path"
	"slices"
	"sync"
	"time"

	"sftpit/internal/sftpwire"
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
)

// Options configures a session.
type Options struct {
	// Faults chooses the fault, if any, for each request the proxy would
	// forward. It is called once per request, in request order, and must not
	// block. A nil Faults, or a nil Action, lets requests through unchanged.
	Faults func(Request) Action

	// Conn is the client's connection, which Drop and Freeze act on. It is
	// required if Faults can return either.
	Conn Conn

	// Logger receives injected faults and, at debug level, every request.
	// Nil means slog.Default().
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
// ends it, a fault drops the connection or ctx is cancelled, and closes both
// before returning. It returns nil when the client ends the session or a
// Drop or Freeze closes the connection, or ctx.Err() if ctx is cancelled
// first. Every fault wait has ended by the time Serve returns, so no request
// reaches the backend afterwards.
//
// Replies reach the client in the order of its requests. A malformed client
// request ends the session, as it does in OpenSSH's sftp-server, and so does
// a backend reply that does not fit its request.
func Serve(ctx context.Context, client, backend io.ReadWriteCloser, opts Options) error {
	s := &session{
		client:    client,
		clientIn:  bufio.NewReader(client),
		backend:   backend,
		backendIn: bufio.NewReader(backend),
		faults:    opts.Faults,
		conn:      opts.Conn,
		logger:    opts.Logger,
		replies:   make(chan slot, maxQueuedReplies),
		done:      make(chan struct{}),
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	stopWhenCancelled := context.AfterFunc(ctx, func() { s.stop(ctx.Err()) })
	defer stopWhenCancelled()

	if err := s.start(); err != nil {
		s.stop(err)
		return s.result()
	}
	s.wg.Go(func() { s.stop(s.relayReplies()) })
	s.wg.Go(func() { s.stop(s.writeReplies()) })
	s.stop(s.relayRequests())
	s.wg.Wait()
	return s.result()
}

type session struct {
	client    io.ReadWriteCloser
	clientIn  *bufio.Reader
	backend   io.ReadWriteCloser
	backendIn *bufio.Reader
	faults    func(Request) Action
	conn      Conn
	logger    *slog.Logger
	tracker   *tracker

	// wg tracks every goroutine of the session, including those holding
	// replies for a fault.
	wg sync.WaitGroup

	// version is the VERSION packet sent to the client, sent again if the
	// client repeats INIT, as OpenSSH and pkg/sftp both do.
	version []byte

	replies  chan slot
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
	if errors.Is(s.err, io.EOF) || errors.Is(s.err, errDropped) {
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
// ends the session.
func (s *session) relayRequests() error {
	for {
		b, err := sftpwire.ReadPacket(s.clientIn, maxPacketLength)
		if err != nil {
			return err
		}
		if err := s.handleRequest(b); err != nil {
			return err
		}
	}
}

func (s *session) handleRequest(b []byte) error {
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
	if s.faults != nil {
		req.action = s.faults(Request{Packet: p, Path: req.path, Target: req.target})
	}
	switch req.action.(type) {
	case Drop, Freeze:
		if s.conn == nil {
			return fmt.Errorf("sftpproxy: a %T fault needs Options.Conn", req.action)
		}
	}
	req.reply = make(slot, 1)
	if err := s.enqueue(req.reply); err != nil {
		return err
	}
	return s.forward(req)
}

// forward passes req to the backend, first applying its fault if that acts
// before the backend. It returns only once req has been forwarded or
// answered, so no later request overtakes it.
func (s *session) forward(req *request) error {
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
			req.reply <- outcome{packet: sftpwire.AppendPacket(nil, req.clientID, status(a.Status))}
			return nil
		case Drop, Freeze:
			req.reply <- outcome{drop: req}
			return s.halt()
		}
	}

	s.tracker.register(req)
	if _, err := s.backend.Write(sftpwire.AppendPacket(nil, req.proxyID, req.packet)); err != nil {
		return fmt.Errorf("sftpproxy: write backend request: %w", err)
	}
	switch req.action.(type) {
	case Drop, Freeze:
		return s.halt()
	}
	return nil
}

// halt forwards no more requests and waits for the session to end, which a
// Drop or Freeze does once every earlier reply has been written.
func (s *session) halt() error {
	<-s.done
	return errStopped
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

// replyNow queues a reply the proxy already has, behind any earlier ones.
func (s *session) replyNow(packet []byte) error {
	reply := make(slot, 1)
	reply <- outcome{packet: packet}
	return s.enqueue(reply)
}

// relayReplies hands each backend reply to the slot of its request,
// re-encoded with the client's request ID.
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
		s.logRequest(req, p)
		s.deliver(req, sftpwire.AppendPacket(nil, req.clientID, p))
	}
}

// deliver passes the backend's reply to req on to the client, applying req's
// fault if that acts after the backend. It never waits, so the backend's
// later replies keep flowing.
func (s *session) deliver(req *request, packet []byte) {
	if req.action == nil || req.action.when() != After {
		req.reply <- outcome{packet: packet}
		return
	}
	s.logFault(req)
	switch a := req.action.(type) {
	case Delay:
		s.wg.Go(func() { s.holdReply(req, a.Duration, nil, packet) })
	case Stall:
		s.wg.Go(func() { s.holdReply(req, a.Limit, a.Release, packet) })
	case Fail:
		req.reply <- outcome{packet: sftpwire.AppendPacket(nil, req.clientID, status(a.Status))}
	case Drop, Freeze:
		req.reply <- outcome{drop: req}
	}
}

func (s *session) holdReply(req *request, limit time.Duration, release <-chan struct{}, packet []byte) {
	if s.hold(req, limit, release) == nil {
		req.reply <- outcome{packet: packet}
	}
}

// writeReplies writes replies to the client in the order of its requests.
func (s *session) writeReplies() error {
	for {
		var next slot
		select {
		case next = <-s.replies:
		case <-s.done:
			return errStopped
		}
		select {
		case out := <-next:
			if out.drop != nil {
				return s.drop(out.drop)
			}
			if _, err := s.client.Write(out.packet); err != nil {
				return fmt.Errorf("sftpproxy: write reply: %w", err)
			}
		case <-s.done:
			return errStopped
		}
	}
}

// drop ends the session at req's Drop or Freeze. The connection goes first,
// so the client sees it fail rather than the session close in an orderly way.
func (s *session) drop(req *request) error {
	var err error
	switch a := req.action.(type) {
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
	s.logger.Info("injected fault", s.faultAttrs(req)...)
}

func (s *session) faultAttrs(req *request) []any {
	attrs := []any{"request", operation(req.packet), "path", req.path}
	if req.target != "" {
		attrs = append(attrs, "target", req.target)
	}
	switch a := req.action.(type) {
	case Delay:
		attrs = append(attrs, "fault", "delay", "when", a.When, "duration", a.Duration)
	case Stall:
		attrs = append(attrs, "fault", "stall", "when", a.When, "limit", a.Limit)
	case Fail:
		attrs = append(attrs, "fault", "fail", "when", a.When, "status", a.Status)
	case Drop:
		mode := "fin"
		if a.Reset {
			mode = "rst"
		}
		attrs = append(attrs, "fault", "drop", "when", a.When, "mode", mode)
	case Freeze:
		attrs = append(attrs, "fault", "freeze", "when", a.When, "limit", a.Limit)
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
