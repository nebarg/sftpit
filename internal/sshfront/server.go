// Package sshfront accepts SSH connections from SFTP clients, authenticates
// them against a fixed set of test users and hands each sftp subsystem
// channel to a Handler.
package sshfront

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// ErrServerClosed is returned by Serve after Close has been called.
var ErrServerClosed = errors.New("sshfront: server closed")

const (
	defaultHandshakeTimeout = 2 * time.Minute
	minAcceptRetryDelay     = 5 * time.Millisecond
	maxAcceptRetryDelay     = time.Second
)

var (
	errInvalidCredentials = errors.New("sshfront: invalid credentials")
	errHandlerPanicked    = errors.New("sshfront: handler panicked")
)

// User is a test account that clients can log in as.
type User struct {
	Name string

	// Password enables password and keyboard-interactive login when non-empty.
	Password string

	// AuthorizedKeys enables public-key login with any of these keys.
	AuthorizedKeys []ssh.PublicKey

	// Home is the user's default directory as an absolute virtual path.
	// Empty means "/".
	Home string
}

// Handler serves one sftp subsystem channel. ctx is cancelled when the
// connection ends. The channel is closed when Handler returns, and a non-nil
// error is reported to the client as exit status 1. A panic is logged with
// its stack trace and reported the same way; other connections are unaffected.
type Handler func(ctx context.Context, conn *Conn, channel io.ReadWriteCloser) error

// Hooks are called at points of each connection's handshake, which waits for
// them to return. A hook may close, reset or freeze the connection, which
// ends the handshake. Its ctx is done once the connection is closed or the
// handshake timeout passes, which bounds the whole handshake, the hooks
// included. Either hook may be nil.
type Hooks struct {
	// Connect is called as a connection is accepted, before the SSH
	// handshake begins. The client has not logged in yet, so the connection
	// has only its ID.
	Connect func(ctx context.Context, conn *Conn)

	// Authenticate is called once the server has verified a client's
	// credentials, before it tells the client that it has logged in.
	Authenticate func(ctx context.Context, conn *Conn)
}

// Config configures a Server.
type Config struct {
	// HostKeys identify the server to clients. At least one is required.
	HostKeys []ssh.Signer

	// Users are the accounts clients can log in as. At least one is required.
	Users []User

	// Handler serves each sftp subsystem channel.
	Handler Handler

	// Hooks are called during each connection's handshake.
	Hooks Hooks

	// HandshakeTimeout bounds the SSH handshake and authentication.
	// Zero means 2 minutes, matching OpenSSH's default LoginGraceTime.
	HandshakeTimeout time.Duration

	// Logger receives connection-level failures. Nil means slog.Default().
	Logger *slog.Logger
}

// Server accepts SSH connections and serves sftp subsystem channels through
// its Handler. Only session channels with the sftp subsystem are accepted;
// shells, commands, ptys, other subsystems and port forwarding are refused.
type Server struct {
	handler          Handler
	hooks            Hooks
	handshakeTimeout time.Duration
	logger           *slog.Logger
	users            map[string]User
	sshConfig        *ssh.ServerConfig
	nextConnID       atomic.Uint64

	mu        sync.Mutex
	closed    bool
	done      chan struct{}
	listeners map[net.Listener]struct{}
	conns     map[*gate]struct{}
	wg        sync.WaitGroup
}

// New validates cfg and returns a Server ready to Serve.
func New(cfg Config) (*Server, error) {
	if len(cfg.HostKeys) == 0 {
		return nil, errors.New("sshfront: at least one host key is required")
	}
	if cfg.Handler == nil {
		return nil, errors.New("sshfront: a handler is required")
	}
	users, err := indexUsers(cfg.Users)
	if err != nil {
		return nil, err
	}

	s := &Server{
		handler:          cfg.Handler,
		hooks:            cfg.Hooks,
		handshakeTimeout: cfg.HandshakeTimeout,
		logger:           cfg.Logger,
		users:            users,
		done:             make(chan struct{}),
		listeners:        make(map[net.Listener]struct{}),
		conns:            make(map[*gate]struct{}),
	}
	if s.handshakeTimeout == 0 {
		s.handshakeTimeout = defaultHandshakeTimeout
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}

	s.sshConfig = &ssh.ServerConfig{
		PasswordCallback:            s.checkPassword,
		KeyboardInteractiveCallback: s.challengePassword,
		PublicKeyCallback:           s.checkPublicKey,
	}
	for _, key := range cfg.HostKeys {
		s.sshConfig.AddHostKey(key)
	}
	return s, nil
}

func indexUsers(users []User) (map[string]User, error) {
	if len(users) == 0 {
		return nil, errors.New("sshfront: at least one user is required")
	}
	byName := make(map[string]User, len(users))
	for _, u := range users {
		if u.Name == "" {
			return nil, errors.New("sshfront: every user needs a name")
		}
		if _, exists := byName[u.Name]; exists {
			return nil, fmt.Errorf("sshfront: duplicate user %q", u.Name)
		}
		if u.Password == "" && len(u.AuthorizedKeys) == 0 {
			return nil, fmt.Errorf("sshfront: user %q needs a password or an authorized key", u.Name)
		}
		if u.Home == "" {
			u.Home = "/"
		}
		if !path.IsAbs(u.Home) {
			return nil, fmt.Errorf("sshfront: user %q home %q is not an absolute path", u.Name, u.Home)
		}
		u.Home = path.Clean(u.Home)
		byName[u.Name] = u
	}
	return byName, nil
}

// Serve accepts connections on ln until Close is called, then returns
// ErrServerClosed. Accept failures such as running out of file descriptors
// are logged and retried with a growing delay of up to one second. Serve
// returns any other error only if ln is closed by someone other than Close.
// Serve always closes ln before returning.
func (s *Server) Serve(ln net.Listener) error {
	defer ln.Close()
	if !s.trackListener(ln) {
		return ErrServerClosed
	}
	defer s.untrackListener(ln)

	var retryDelay time.Duration
	for {
		nc, err := ln.Accept()
		if err != nil {
			if s.isClosed() {
				return ErrServerClosed
			}
			if errors.Is(err, net.ErrClosed) {
				return fmt.Errorf("sshfront: accept: %w", err)
			}
			retryDelay = min(max(2*retryDelay, minAcceptRetryDelay), maxAcceptRetryDelay)
			s.logger.Warn("accept failed; retrying", "err", err, "delay", retryDelay)
			select {
			case <-time.After(retryDelay):
				continue
			case <-s.done:
				return ErrServerClosed
			}
		}
		retryDelay = 0

		g := newGate(nc)
		if !s.trackConn(g) {
			g.Close()
			return ErrServerClosed
		}
		go s.serveConn(g)
	}
}

// Close stops every listener, closes every connection, including those still
// handshaking, and waits for their handlers to return.
func (s *Server) Close() error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.done)
	}
	var errs []error
	for ln := range s.listeners {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	for g := range s.conns {
		g.abort()
	}
	s.mu.Unlock()

	s.wg.Wait()
	return errors.Join(errs...)
}

func (s *Server) trackListener(ln net.Listener) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.listeners[ln] = struct{}{}
	return true
}

func (s *Server) untrackListener(ln net.Listener) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.listeners, ln)
}

// trackConn registers g with the wait group under the same lock that Close
// takes, so Close never waits on a group that is still being added to.
func (s *Server) trackConn(g *gate) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[g] = struct{}{}
	s.wg.Add(1)
	return true
}

func (s *Server) untrackConn(g *gate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, g)
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Server) serveConn(g *gate) {
	defer s.wg.Done()
	defer s.untrackConn(g)
	defer g.Close()

	conn := &Conn{id: s.nextConnID.Add(1), gate: g}
	channels, requests, ok := s.handshake(conn)
	if !ok {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { ssh.DiscardRequests(requests) })
	for nc := range channels {
		wg.Go(func() { s.serveChannel(ctx, conn, nc) })
	}
	cancel()
	wg.Wait()
}

// handshake runs conn's SSH handshake, calling the hooks along the way, and
// returns the connection's channels and requests, or false if it fails.
func (s *Server) handshake(conn *Conn) (<-chan ssh.NewChannel, <-chan *ssh.Request, bool) {
	g := conn.gate
	deadline := time.Now().Add(s.handshakeTimeout)
	if err := g.SetDeadline(deadline); err != nil {
		s.logger.Warn("setting handshake deadline failed", "conn", conn.id, "remote", g.RemoteAddr(), "err", err)
		return nil, nil, false
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	go func() {
		select {
		case <-g.closed:
			cancel()
		case <-ctx.Done():
		}
	}()

	if s.hooks.Connect != nil {
		s.hooks.Connect(ctx, conn)
	}
	sc, channels, requests, err := ssh.NewServerConn(g, s.handshakeConfig(ctx, conn))
	// A connection closed on purpose, by a hook or by Close, has not failed.
	// The handshake can even seem to succeed: the library reports a failure
	// to send its last message only to later writes.
	if g.deliberate.Load() {
		if err == nil {
			sc.Close()
		}
		s.logger.Debug("ssh handshake ended by the server", "conn", conn.id, "remote", g.RemoteAddr())
		return nil, nil, false
	}
	if err != nil {
		s.logger.Info("ssh handshake failed", "conn", conn.id, "remote", g.RemoteAddr(), "err", err)
		return nil, nil, false
	}
	if err := g.SetDeadline(time.Time{}); err != nil {
		s.logger.Warn("clearing handshake deadline failed", "conn", conn.id, "remote", g.RemoteAddr(), "err", err)
		return nil, nil, false
	}
	return channels, requests, true
}

// handshakeConfig returns the SSH configuration for conn's handshake, which
// records who the client logs in as and calls the Authenticate hook before
// telling the client.
func (s *Server) handshakeConfig(ctx context.Context, conn *Conn) *ssh.ServerConfig {
	cfg := *s.sshConfig
	cfg.VerifiedPublicKeyCallback = func(_ ssh.ConnMetadata, key ssh.PublicKey, perms *ssh.Permissions, _ string) (*ssh.Permissions, error) {
		conn.keyFingerprint = ssh.FingerprintSHA256(key)
		return perms, nil
	}
	// The library calls AuthLogCallback with a nil error once a login has
	// succeeded, before it tells the client.
	cfg.AuthLogCallback = func(meta ssh.ConnMetadata, _ string, err error) {
		if err != nil {
			return
		}
		user := s.users[meta.User()]
		conn.user, conn.home = user.Name, user.Home
		if s.hooks.Authenticate != nil {
			s.hooks.Authenticate(ctx, conn)
		}
		conn.authenticated = time.Now()
	}
	return &cfg
}

func (s *Server) serveChannel(ctx context.Context, conn *Conn, nc ssh.NewChannel) {
	if nc.ChannelType() != "session" {
		if err := nc.Reject(ssh.UnknownChannelType, "only session channels are supported"); err != nil {
			s.logger.Debug("rejecting channel failed", "conn", conn.id, "type", nc.ChannelType(), "err", err)
		}
		return
	}
	channel, requests, err := nc.Accept()
	if err != nil {
		s.logger.Info("accepting session channel failed", "conn", conn.id, "err", err)
		return
	}

	var handlerDone chan struct{}
	for req := range requests {
		accept := handlerDone == nil && req.Type == "subsystem" && subsystemName(req.Payload) == "sftp"
		if err := req.Reply(accept, nil); err != nil {
			break
		}
		if accept {
			handlerDone = make(chan struct{})
			go func() {
				defer close(handlerDone)
				s.runHandler(ctx, conn, channel)
			}()
		}
	}

	if handlerDone == nil {
		channel.Close()
		return
	}
	<-handlerDone
}

func (s *Server) runHandler(ctx context.Context, conn *Conn, channel ssh.Channel) {
	defer channel.Close()

	var status uint32
	if err := s.callHandler(ctx, conn, channel); err != nil {
		status = 1
	}
	exitStatus := ssh.Marshal(struct{ Status uint32 }{status})
	if _, err := channel.SendRequest("exit-status", false, exitStatus); err != nil {
		s.logger.Debug("sending exit status failed", "conn", conn.id, "err", err)
	}
}

// callHandler contains a panic to the one channel that caused it: an
// unrecovered panic in any goroutine would otherwise stop the whole process,
// including every other connection.
func (s *Server) callHandler(ctx context.Context, conn *Conn, channel ssh.Channel) (err error) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("sftp handler panicked", "conn", conn.id, "user", conn.user, "panic", r, "stack", string(debug.Stack()))
			err = errHandlerPanicked
		}
	}()

	err = s.handler(ctx, conn, channel)
	switch {
	case err == nil:
	case ctx.Err() != nil && errors.Is(err, ctx.Err()):
		// The connection ended, and the handler stopped because of it.
		s.logger.Debug("sftp handler stopped with its connection", "conn", conn.id, "user", conn.user)
	default:
		s.logger.Warn("sftp handler failed", "conn", conn.id, "user", conn.user, "err", err)
	}
	return err
}

func subsystemName(payload []byte) string {
	var msg struct{ Name string }
	if err := ssh.Unmarshal(payload, &msg); err != nil {
		return ""
	}
	return msg.Name
}

func (s *Server) checkPassword(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	if !s.passwordMatches(meta.User(), password) {
		return nil, errInvalidCredentials
	}
	return &ssh.Permissions{}, nil
}

func (s *Server) challengePassword(meta ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	answers, err := challenge("", "", []string{"Password: "}, []bool{false})
	if err != nil {
		return nil, err
	}
	if len(answers) != 1 || !s.passwordMatches(meta.User(), []byte(answers[0])) {
		return nil, errInvalidCredentials
	}
	return &ssh.Permissions{}, nil
}

func (s *Server) passwordMatches(name string, password []byte) bool {
	u, ok := s.users[name]
	return ok && u.Password != "" && subtle.ConstantTimeCompare(password, []byte(u.Password)) == 1
}

func (s *Server) checkPublicKey(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	u, ok := s.users[meta.User()]
	if !ok {
		return nil, errInvalidCredentials
	}
	offered := key.Marshal()
	for _, authorized := range u.AuthorizedKeys {
		if bytes.Equal(authorized.Marshal(), offered) {
			return &ssh.Permissions{}, nil
		}
	}
	return nil, errInvalidCredentials
}
