package sshfront

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Conn is a client connection. Its methods are safe for concurrent use. Its
// user, home and key fingerprint are set once the client has logged in, so
// a Handler sees them but Hooks.Connect does not.
type Conn struct {
	id             uint64
	user           string
	home           string
	keyFingerprint string
	authenticated  time.Time
	server         *Server
	gate           *gate
}

// ID identifies the connection uniquely within its Server.
func (c *Conn) ID() uint64 { return c.id }

// User returns the name the client authenticated as.
func (c *Conn) User() string { return c.user }

// Home returns the user's default directory.
func (c *Conn) Home() string { return c.home }

// KeyFingerprint returns the SHA256 fingerprint of the public key the client
// authenticated with, or "" if it logged in with a password.
func (c *Conn) KeyFingerprint() string { return c.keyFingerprint }

// Authenticated returns when the client finished logging in: when the
// server, any Hooks.Authenticate having returned, went on to tell it.
func (c *Conn) Authenticated() time.Time { return c.authenticated }

// Server returns the server that accepted the connection.
func (c *Conn) Server() *Server { return c.server }

// Close closes the connection normally, so the client sees a TCP FIN. The
// server stops reading and writing at once, but discards whatever the client
// still sends until it closes its end, for up to a second: closing with data
// unread, as there may be during an upload, makes the kernel reset the
// connection instead.
func (c *Conn) Close() error { return c.gate.closeNormally() }

// Reset aborts the connection so the client sees a TCP reset rather than a
// normal close.
func (c *Conn) Reset() error { return c.gate.reset() }

// Freeze stops traffic in both directions until Close. The client sees
// neither data nor a close, so its SSH keepalives go unanswered. A write
// already in progress is not interrupted. Callers must bound how long a
// connection stays frozen.
func (c *Conn) Freeze() { c.gate.freeze() }

// drainTimeout bounds how long a normal close waits for the client to close
// its end, which a client that has seen the FIN does at once.
const drainTimeout = time.Second

type gate struct {
	net.Conn

	frozen     chan struct{}
	freezeOnce sync.Once

	mu sync.Mutex
	// draining is set by a normal close, which leaves the connection open
	// for Close to drain.
	draining bool

	closed    chan struct{}
	closeOnce sync.Once

	// deliberate is set when the server closes the connection on purpose,
	// through Conn or as it shuts down, rather than the SSH layer closing it
	// on a failure.
	deliberate atomic.Bool
}

func newGate(c net.Conn) *gate {
	return &gate{Conn: c, frozen: make(chan struct{}), closed: make(chan struct{})}
}

func (g *gate) Read(p []byte) (int, error) {
	if err := g.wait(); err != nil {
		return 0, err
	}
	n, err := g.Conn.Read(p)
	// A read that was already blocked when Freeze or a normal close was
	// called must not hand its data to the SSH layer.
	if werr := g.wait(); werr != nil {
		return 0, werr
	}
	return n, err
}

func (g *gate) Write(p []byte) (int, error) {
	if err := g.wait(); err != nil {
		return 0, err
	}
	return g.Conn.Write(p)
}

// Close closes the connection, after draining it if a normal close has begun.
func (g *gate) Close() error {
	g.closeOnce.Do(func() { close(g.closed) })
	if g.isDraining() {
		// The client closing its end, or the read deadline that
		// closeNormally set, ends the drain.
		_, _ = io.Copy(io.Discard, g.Conn)
	}
	return g.Conn.Close()
}

// abort closes the connection at once, cutting any drain short.
func (g *gate) abort() error {
	g.deliberate.Store(true)
	g.closeOnce.Do(func() { close(g.closed) })
	return g.Conn.Close()
}

// closeNormally stops the SSH layer reading and writing and sends the client
// a FIN, leaving the connection to be drained and closed once the SSH layer
// has ended. A connection other than TCP is closed at once.
func (g *gate) closeNormally() error {
	g.deliberate.Store(true)
	tcp, ok := g.Conn.(*net.TCPConn)
	if !ok {
		return g.Close()
	}
	again, err := g.startDrain(tcp)
	if again || err != nil {
		return err
	}
	if err := tcp.CloseWrite(); err != nil {
		// The connection is already closed or reset, so there is nothing to
		// drain.
		return g.abort()
	}
	// Once stopped, the SSH layer closes the connection as it ends, so it
	// must not stop before the FIN has gone.
	g.closeOnce.Do(func() { close(g.closed) })
	return nil
}

// startDrain begins a normal close and sets the read deadline that bounds
// its drain, under mu so that endHandshake cannot clear it. It reports
// whether a normal close had already begun.
func (g *gate) startDrain(tcp *net.TCPConn) (again bool, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.draining {
		return true, nil
	}
	g.draining = true
	if err := tcp.SetReadDeadline(time.Now().Add(drainTimeout)); err != nil {
		return false, fmt.Errorf("sshfront: close: %w", err)
	}
	return false, nil
}

// endHandshake clears the handshake's deadline, unless a normal close has
// begun and set the one that bounds its drain.
func (g *gate) endHandshake() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.draining {
		return nil
	}
	return g.SetDeadline(time.Time{})
}

func (g *gate) isDraining() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.draining
}

func (g *gate) freeze() { g.freezeOnce.Do(func() { close(g.frozen) }) }

// wait returns net.ErrClosed once the connection is closed, and until then
// blocks while it is frozen.
func (g *gate) wait() error {
	select {
	case <-g.closed:
		return net.ErrClosed
	case <-g.frozen:
		<-g.closed
		return net.ErrClosed
	default:
		return nil
	}
}

func (g *gate) reset() error {
	g.deliberate.Store(true)
	tcp, ok := g.Conn.(*net.TCPConn)
	if !ok {
		return errors.New("sshfront: reset needs a TCP connection")
	}
	if err := tcp.SetLinger(0); err != nil {
		return fmt.Errorf("sshfront: reset: %w", err)
	}
	return g.Close()
}
