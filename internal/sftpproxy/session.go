// Package sftpproxy relays SFTP sessions between a client and a backend
// server, decoding every packet in both directions. The proxy negotiates with
// each side separately, owns the request IDs on the backend, resolves every
// client path against the backend's default directory and tracks which path
// each open handle refers to, so every request can be attributed to a file.
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
)

// Serve relays one SFTP session from client to backend until either side
// ends it or ctx is cancelled, and closes both before returning. It returns
// nil when the client ends the session, or ctx.Err() if ctx is cancelled
// first. A nil logger means slog.Default().
//
// Replies reach the client in the order of its requests. A malformed client
// request ends the session, as it does in OpenSSH's sftp-server, and so does
// a backend reply that does not fit its request.
func Serve(ctx context.Context, client, backend io.ReadWriteCloser, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	s := &session{
		client:    client,
		clientIn:  bufio.NewReader(client),
		backend:   backend,
		backendIn: bufio.NewReader(backend),
		logger:    logger,
		replies:   make(chan slot, maxQueuedReplies),
		done:      make(chan struct{}),
	}
	stopWhenCancelled := context.AfterFunc(ctx, func() { s.stop(ctx.Err()) })
	defer stopWhenCancelled()

	if err := s.start(); err != nil {
		s.stop(err)
		return s.result()
	}
	var wg sync.WaitGroup
	wg.Go(func() { s.stop(s.relayReplies()) })
	wg.Go(func() { s.stop(s.writeReplies()) })
	s.stop(s.relayRequests())
	wg.Wait()
	return s.result()
}

type session struct {
	client    io.ReadWriteCloser
	clientIn  *bufio.Reader
	backend   io.ReadWriteCloser
	backendIn *bufio.Reader
	logger    *slog.Logger
	tracker   *tracker

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
	if errors.Is(s.err, io.EOF) {
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

	reply := make(slot, 1)
	req, rejection := s.tracker.track(clientID, p, reply)
	if rejection != nil {
		s.logRequest(req, rejection)
		return s.replyNow(sftpwire.AppendPacket(nil, clientID, rejection))
	}
	if err := s.enqueue(reply); err != nil {
		return err
	}
	if _, err := s.backend.Write(sftpwire.AppendPacket(nil, req.proxyID, p)); err != nil {
		return fmt.Errorf("sftpproxy: write backend request: %w", err)
	}
	return nil
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
	reply <- packet
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
		req.reply <- sftpwire.AppendPacket(nil, req.clientID, p)
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
		case packet := <-next:
			if _, err := s.client.Write(packet); err != nil {
				return fmt.Errorf("sftpproxy: write reply: %w", err)
			}
		case <-s.done:
			return errStopped
		}
	}
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
