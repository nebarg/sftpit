package sshfront

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Conn is an authenticated client connection. Its methods are safe for
// concurrent use.
type Conn struct {
	id             uint64
	user           string
	home           string
	keyFingerprint string
	ssh            *ssh.ServerConn
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

// Close closes the connection normally, so the client sees a TCP FIN.
func (c *Conn) Close() error { return c.ssh.Close() }

// Reset aborts the connection so the client sees a TCP reset rather than a
// normal close.
func (c *Conn) Reset() error { return c.gate.reset() }

// Freeze stops traffic in both directions until Thaw or Close. The client
// sees neither data nor a close, so its SSH keepalives go unanswered. A write
// already in progress is not interrupted. Callers must bound how long a
// connection stays frozen.
func (c *Conn) Freeze() { c.gate.freeze() }

// Thaw resumes traffic after Freeze. Data that arrived while frozen is then
// delivered in order.
func (c *Conn) Thaw() { c.gate.thaw() }

type gate struct {
	net.Conn

	mu        sync.Mutex
	flowing   chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
}

func newGate(c net.Conn) *gate {
	flowing := make(chan struct{})
	close(flowing)
	return &gate{Conn: c, flowing: flowing, closed: make(chan struct{})}
}

func (g *gate) Read(p []byte) (int, error) {
	if err := g.wait(); err != nil {
		return 0, err
	}
	n, err := g.Conn.Read(p)
	// A read that was already blocked when Freeze was called must not hand
	// its data to the SSH layer until the connection thaws.
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

func (g *gate) Close() error {
	g.closeOnce.Do(func() { close(g.closed) })
	return g.Conn.Close()
}

func (g *gate) freeze() {
	g.mu.Lock()
	defer g.mu.Unlock()
	select {
	case <-g.flowing:
		g.flowing = make(chan struct{})
	default:
	}
}

func (g *gate) thaw() {
	g.mu.Lock()
	defer g.mu.Unlock()
	select {
	case <-g.flowing:
	default:
		close(g.flowing)
	}
}

func (g *gate) wait() error {
	g.mu.Lock()
	flowing := g.flowing
	g.mu.Unlock()
	select {
	case <-flowing:
		return nil
	case <-g.closed:
		return net.ErrClosed
	}
}

func (g *gate) reset() error {
	tcp, ok := g.Conn.(*net.TCPConn)
	if !ok {
		return errors.New("sshfront: reset needs a TCP connection")
	}
	if err := tcp.SetLinger(0); err != nil {
		return fmt.Errorf("sshfront: reset: %w", err)
	}
	return g.Close()
}
