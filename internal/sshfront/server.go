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
	errDown               = errors.New("sshfront: server down")
	errPaused             = errors.New("sshfront: admission closed")
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

	mu     sync.Mutex
	closed bool
	done   chan struct{}
	// listeners maps each listener Serve accepts on to whether an outage
	// has closed it.
	listeners map[net.Listener]bool
	// conns maps each connection to a channel that is closed once it has
	// ended.
	conns map[*gate]chan struct{}
	// outage is set while the server is down.
	outage *outage
	// paused is set while admission is closed.
	paused bool
	wg     sync.WaitGroup
}

// outage is a span in which a server accepts no connections.
type outage struct {
	until time.Time
	timer *time.Timer
	// over is closed when the outage ends.
	over chan struct{}
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
		listeners:        make(map[net.Listener]bool),
		conns:            make(map[*gate]chan struct{}),
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
// returns any other error only if ln is closed by someone other than Close
// or Down. When Down closes ln, Serve listens on ln's address again once the
// outage is over, with a listener of its own, so whatever ln adds to the
// listener it wraps does not outlast the outage. Serve always closes the
// listener it accepts on before returning.
func (s *Server) Serve(ln net.Listener) error {
	addr := ln.Addr()
	for {
		err := s.accept(ln)
		if !errors.Is(err, errDown) {
			return err
		}
		if ln, err = s.listenAgain(addr); err != nil {
			return err
		}
	}
}

// accept accepts connections on ln until Close or Down closes it, and
// returns ErrServerClosed or errDown.
func (s *Server) accept(ln net.Listener) error {
	defer ln.Close()
	if err := s.trackListener(ln); err != nil {
		return err
	}
	defer s.untrackListener(ln)

	var retryDelay time.Duration
	for {
		nc, err := ln.Accept()
		if err != nil {
			if s.isClosed() {
				return ErrServerClosed
			}
			if s.closedByOutage(ln) {
				return errDown
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
		switch err := s.trackConn(g); {
		case errors.Is(err, errDown):
			// The connection came in as the outage began.
			g.Close()
			continue
		case errors.Is(err, errPaused):
			s.logger.Info("closed a connection while admission is closed", "remote", g.RemoteAddr())
			g.Close()
			continue
		case err != nil:
			g.Close()
			return err
		}
		go s.serveConn(g)
	}
}

// listenAgain waits for the outage to end, then listens on addr, retrying
// with a growing delay of up to one second if that fails.
func (s *Server) listenAgain(addr net.Addr) (net.Listener, error) {
	var retryDelay time.Duration
	for {
		if over := s.outageOver(); over != nil {
			select {
			case <-over:
			case <-s.done:
				return nil, ErrServerClosed
			}
		}
		ln, err := net.Listen(addr.Network(), addr.String())
		if err == nil {
			s.logger.Info("listening again after an outage", "addr", ln.Addr())
			return ln, nil
		}
		retryDelay = min(max(2*retryDelay, minAcceptRetryDelay), maxAcceptRetryDelay)
		s.logger.Warn("listening again after an outage failed; retrying", "addr", addr, "err", err, "delay", retryDelay)
		select {
		case <-time.After(retryDelay):
		case <-s.done:
			return nil, ErrServerClosed
		}
	}
}

// Down takes the server down for d. It closes every listener Serve accepts
// on, so that new connections are refused, and Serve listens on each one's
// address again once d has passed. A connection accepted as the outage
// begins is closed at once. If closeExisting, Down also closes every
// connection, as Conn.Close does. Down while the server is down extends the
// outage if it would end later. Down does nothing while admission is closed.
func (s *Server) Down(d time.Duration, closeExisting bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.paused {
		return
	}
	until := time.Now().Add(d)
	switch o := s.outage; {
	case o == nil:
		o = &outage{until: until, over: make(chan struct{})}
		o.timer = time.AfterFunc(d, func() { s.endOutage(o) })
		s.outage = o
		for ln := range s.listeners {
			s.listeners[ln] = true
			if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				s.logger.Warn("closing a listener for an outage failed", "addr", ln.Addr(), "err", err)
			}
		}
	case until.After(o.until):
		o.until = until
	}
	if closeExisting {
		for g := range s.conns {
			g.closeNormally()
		}
	}
}

// endOutage ends o, unless Down has since extended it.
func (s *Server) endOutage(o *outage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.outage != o {
		return
	}
	if left := time.Until(o.until); left > 0 {
		o.timer.Reset(left)
		return
	}
	s.outage = nil
	close(o.over)
}

// Outage returns when the current outage ends, and false if the server is
// up.
func (s *Server) Outage() (until time.Time, down bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.outage == nil {
		return time.Time{}, false
	}
	return s.outage.until, true
}

// Pause closes admission and ends every connection, so that what serves
// them can change while no client is connected. Until Resume, the server
// accepts each new connection and closes it before its handshake, keeping
// its listeners open, and Down does nothing. An outage ends, so that Serve
// listens again. Pause closes every connection, as Conn.Close does, and
// waits until each has ended, its handlers included, or until ctx is done,
// whose error it then returns. Admission stays closed however Pause returns.
func (s *Server) Pause(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrServerClosed
	}
	s.paused = true
	if o := s.outage; o != nil {
		o.timer.Stop()
		s.outage = nil
		close(o.over)
	}
	ended := make([]chan struct{}, 0, len(s.conns))
	for g, done := range s.conns {
		g.closeNormally()
		ended = append(ended, done)
	}
	s.mu.Unlock()

	for _, done := range ended {
		select {
		case <-done:
		case <-ctx.Done():
			return fmt.Errorf("sshfront: pause: %w", ctx.Err())
		}
	}
	return nil
}

// Resume admits connections again after Pause.
func (s *Server) Resume() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.paused = false
}

// outageOver returns a channel that is closed when the outage ends, or nil
// if the server is up.
func (s *Server) outageOver() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.outage == nil {
		return nil
	}
	return s.outage.over
}

func (s *Server) closedByOutage(ln net.Listener) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listeners[ln]
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
	if s.outage != nil {
		s.outage.timer.Stop()
	}
	s.mu.Unlock()

	s.wg.Wait()
	return errors.Join(errs...)
}

// trackListener registers ln, unless the server is closed or down.
func (s *Server) trackListener(ln net.Listener) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.closed:
		return ErrServerClosed
	case s.outage != nil:
		return errDown
	}
	s.listeners[ln] = false
	return nil
}

func (s *Server) untrackListener(ln net.Listener) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.listeners, ln)
}

// trackConn registers g with the wait group under the same lock that Close
// takes, so Close never waits on a group that is still being added to. It
// refuses g if the server is closed or down, or admission is closed.
func (s *Server) trackConn(g *gate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.closed:
		return ErrServerClosed
	case s.outage != nil:
		return errDown
	case s.paused:
		return errPaused
	}
	s.conns[g] = make(chan struct{})
	s.wg.Add(1)
	return nil
}

func (s *Server) untrackConn(g *gate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	close(s.conns[g])
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

	conn := &Conn{id: s.nextConnID.Add(1), server: s, gate: g}
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
