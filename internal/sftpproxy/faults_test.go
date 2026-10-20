package sftpproxy_test

import (
	"bufio"
	"context"
	"errors"
	"log/slog"
	"net"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"sftpit/internal/sftpproxy"
	"sftpit/internal/sftpwire"
)

func TestDelayBeforeHoldsTheRequestAndEveryLaterOne(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := startFaultProxy(t, context.Background(), onPath("/slow", sftpproxy.Delay{When: sftpproxy.Before, Duration: 3 * time.Second}), nil)
		start := time.Now()
		p.client.sendTogether(t, &sftpwire.Stat{Path: "/slow"}, &sftpwire.Stat{Path: "/other"})

		p.assertNoBackendRequest(t)
		slow := p.backend.next(t)
		if got := time.Since(start); got != 3*time.Second {
			t.Errorf("backend received the delayed request after %v, want 3s", got)
		}
		other := p.backend.next(t)
		assertPaths(t, []backendRequest{slow, other}, "/slow", "/other")

		p.backend.reply(t, slow.id, &sftpwire.AttrsReply{})
		p.backend.reply(t, other.id, &sftpwire.AttrsReply{})
		p.client.assertReplies(t, 1, 2)
	})
}

func TestDelayAfterHoldsTheReplyAndEveryLaterOne(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := startFaultProxy(t, context.Background(), onPath("/slow", sftpproxy.Delay{When: sftpproxy.After, Duration: 3 * time.Second}), nil)
		start := time.Now()
		p.client.sendTogether(t, &sftpwire.Stat{Path: "/slow"}, &sftpwire.Stat{Path: "/other"})

		slow, other := p.backend.next(t), p.backend.next(t)
		assertPaths(t, []backendRequest{slow, other}, "/slow", "/other")
		p.backend.reply(t, slow.id, &sftpwire.AttrsReply{})
		p.backend.reply(t, other.id, &sftpwire.AttrsReply{})

		p.client.assertReplies(t, 1)
		if got := time.Since(start); got != 3*time.Second {
			t.Errorf("client received the delayed reply after %v, want 3s", got)
		}
		p.client.assertReplies(t, 2)
	})
}

func TestStallEndsAtReleaseOrLimit(t *testing.T) {
	tests := []struct {
		name    string
		when    sftpproxy.When
		release bool
		want    time.Duration
	}{
		{name: "before, released", when: sftpproxy.Before, release: true, want: time.Second},
		{name: "before, at the limit", when: sftpproxy.Before, want: 4 * time.Second},
		{name: "after, released", when: sftpproxy.After, release: true, want: time.Second},
		{name: "after, at the limit", when: sftpproxy.After, want: 4 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var logs syncBuffer
				release := make(chan struct{})
				stall := sftpproxy.Stall{When: tt.when, Release: release, Limit: 4 * time.Second}
				p := startFaultProxy(t, context.Background(), onPath("/a", stall), &logs)
				start := time.Now()
				p.client.send(t, 1, &sftpwire.Stat{Path: "/a"})
				if tt.release {
					time.AfterFunc(time.Second, func() { close(release) })
				}

				p.backend.reply(t, p.backend.next(t).id, &sftpwire.AttrsReply{})
				p.client.assertReplies(t, 1)
				if got := time.Since(start); got != tt.want {
					t.Errorf("stall ended after %v, want %v", got, tt.want)
				}
				wantLog := "msg=\"fault ended at its limit\""
				if tt.release {
					wantLog = "msg=\"fault released\""
				}
				if !strings.Contains(logs.String(), wantLog) {
					t.Errorf("log does not contain %s:\n%s", wantLog, logs.String())
				}
			})
		})
	}
}

func TestFailBeforeAnswersWithoutTheBackend(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs syncBuffer
		p := startFaultProxy(t, context.Background(), onPath("/a", sftpproxy.Fail{When: sftpproxy.Before, Status: sftpwire.StatusPermissionDenied}), &logs)
		p.client.sendTogether(t, &sftpwire.Rename{OldPath: "/a", NewPath: "/b"}, &sftpwire.Stat{Path: "/c"})

		stat := p.backend.next(t)
		assertPaths(t, []backendRequest{stat}, "/c")
		p.backend.reply(t, stat.id, &sftpwire.AttrsReply{})
		p.client.assertStatus(t, 1, sftpwire.StatusPermissionDenied, "Permission denied")
		p.client.assertReplies(t, 2)

		want := "msg=\"injected fault\" request=SSH_FXP_RENAME path=/a target=/b fault=fail when=before status=SSH_FX_PERMISSION_DENIED"
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log does not contain %q:\n%s", want, logs.String())
		}
	})
}

func TestFailAfterReplacesTheReply(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := startFaultProxy(t, context.Background(), onPath("/a", sftpproxy.Fail{When: sftpproxy.After, Status: sftpwire.StatusFailure}), nil)
		p.client.send(t, 1, &sftpwire.Rename{OldPath: "/a", NewPath: "/b"})

		rename := p.backend.next(t)
		if _, ok := rename.packet.(*sftpwire.Rename); !ok {
			t.Fatalf("backend received %#v, want the rename", rename.packet)
		}
		p.backend.reply(t, rename.id, &sftpwire.StatusReply{Code: sftpwire.StatusOK})
		p.client.assertStatus(t, 1, sftpwire.StatusFailure, "Failure")
	})
}

func TestCloseFailedBeforeTheBackendKeepsItsHandle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var seen []sftpproxy.Request
		faults := func(r sftpproxy.Request) sftpproxy.Action {
			seen = append(seen, r)
			if _, ok := r.Packet.(*sftpwire.Close); ok {
				return sftpproxy.Fail{When: sftpproxy.Before, Status: sftpwire.StatusFailure}
			}
			return nil
		}
		p := startFaultProxy(t, context.Background(), faults, nil)
		p.client.send(t, 1, &sftpwire.Open{Path: "/a", Flags: sftpwire.OpenRead})
		p.backend.reply(t, p.backend.next(t).id, &sftpwire.HandleReply{Handle: "h"})
		p.client.assertReplies(t, 1)

		p.client.send(t, 2, &sftpwire.Close{Handle: "h"})
		p.client.assertStatus(t, 2, sftpwire.StatusFailure, "Failure")
		p.client.send(t, 3, &sftpwire.Read{Handle: "h", Length: 10})

		read := p.backend.next(t)
		if _, ok := read.packet.(*sftpwire.Read); !ok {
			t.Errorf("backend received %#v, want only the READ", read.packet)
		}
		if got := seen[len(seen)-1].Path; got != "/a" {
			t.Errorf("READ after a failed CLOSE has path %q, want /a", got)
		}
	})
}

func TestFaultsSeeResolvedPaths(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var seen sftpproxy.Request
		faults := func(r sftpproxy.Request) sftpproxy.Action {
			seen = r
			return nil
		}
		fb, backend := startFakeBackend(t, openSSHVersion, "/home/p")
		p := startFaultProxyOn(t, context.Background(), fb, backend, sftpproxy.Options{Faults: faults})
		p.client.send(t, 1, &sftpwire.Rename{OldPath: "a.part", NewPath: "../q/a"})
		p.backend.next(t)

		want := sftpproxy.Request{
			Packet: &sftpwire.Rename{OldPath: "/home/p/a.part", NewPath: "/home/q/a"},
			Path:   "/home/p/a.part",
			Target: "/home/q/a",
		}
		if !reflect.DeepEqual(seen, want) {
			t.Errorf("Faults saw %#v, want %#v", seen, want)
		}
	})
}

func TestDropComesAfterEarlierRepliesAndBeforeLaterRequests(t *testing.T) {
	tests := []struct {
		name  string
		drop  sftpproxy.Drop
		event string
	}{
		{name: "before, FIN", drop: sftpproxy.Drop{When: sftpproxy.Before}, event: "close"},
		{name: "before, RST", drop: sftpproxy.Drop{When: sftpproxy.Before, Reset: true}, event: "reset"},
		{name: "after, FIN", drop: sftpproxy.Drop{When: sftpproxy.After}, event: "close"},
		{name: "after, RST", drop: sftpproxy.Drop{When: sftpproxy.After, Reset: true}, event: "reset"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p := startFaultProxy(t, context.Background(), onPath("/a", tt.drop), nil)
				p.client.sendTogether(t,
					&sftpwire.Stat{Path: "/first"},
					&sftpwire.Rename{OldPath: "/a", NewPath: "/b"},
					&sftpwire.Stat{Path: "/last"},
				)

				first := p.backend.next(t)
				if tt.drop.When == sftpproxy.After {
					rename := p.backend.next(t)
					p.backend.reply(t, rename.id, &sftpwire.StatusReply{Code: sftpwire.StatusOK})
				}
				p.assertNoBackendRequest(t)
				if got := p.conn.events(); len(got) != 0 {
					t.Fatalf("connection %v before the earlier reply was written", got)
				}

				p.backend.reply(t, first.id, &sftpwire.AttrsReply{})
				p.client.assertReplies(t, 1)
				p.client.assertClosed(t)
				if err := p.result.wait(t); err != nil {
					t.Errorf("Serve after a drop = %v, want nil", err)
				}
				if got := p.conn.events(); !slices.Equal(got, []string{tt.event}) {
					t.Errorf("connection events = %v, want [%s]", got, tt.event)
				}
				p.assertNoBackendRequest(t)
			})
		})
	}
}

func TestFreezeClosesAtReleaseOrLimit(t *testing.T) {
	for _, release := range []bool{true, false} {
		name := map[bool]string{true: "released", false: "at the limit"}[release]
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				releaseCh := make(chan struct{})
				freeze := sftpproxy.Freeze{When: sftpproxy.After, Release: releaseCh, Limit: 4 * time.Second}
				p := startFaultProxy(t, context.Background(), onPath("/a", freeze), nil)
				start := time.Now()
				p.client.send(t, 1, &sftpwire.Rename{OldPath: "/a", NewPath: "/b"})
				p.backend.reply(t, p.backend.next(t).id, &sftpwire.StatusReply{Code: sftpwire.StatusOK})

				synctest.Wait()
				if got := p.conn.events(); !slices.Equal(got, []string{"freeze"}) {
					t.Fatalf("connection events = %v, want [freeze]", got)
				}
				want := 4 * time.Second
				if release {
					want = time.Second
					time.Sleep(want)
					close(releaseCh)
				}
				p.client.assertClosed(t)
				if got := time.Since(start); got != want {
					t.Errorf("connection closed after %v, want %v", got, want)
				}
				if got := p.conn.events(); !slices.Equal(got, []string{"freeze", "close"}) {
					t.Errorf("connection events = %v, want [freeze close]", got)
				}
			})
		})
	}
}

// TestFaultWaitsEndWithTheSession checks, in each reply order, that
// cancelling a session ends its fault waits at once, and that a held request
// never reaches the backend.
func TestFaultWaitsEndWithTheSession(t *testing.T) {
	tests := []struct {
		name   string
		action func(release <-chan struct{}) sftpproxy.Action
		after  bool
	}{
		{
			name: "delay before",
			action: func(<-chan struct{}) sftpproxy.Action {
				return sftpproxy.Delay{When: sftpproxy.Before, Duration: time.Hour}
			},
		},
		{
			name: "delay after",
			action: func(<-chan struct{}) sftpproxy.Action {
				return sftpproxy.Delay{When: sftpproxy.After, Duration: time.Hour}
			},
			after: true,
		},
		{
			name: "stall before",
			action: func(release <-chan struct{}) sftpproxy.Action {
				return sftpproxy.Stall{When: sftpproxy.Before, Release: release, Limit: time.Hour}
			},
		},
		{
			name: "stall after",
			action: func(release <-chan struct{}) sftpproxy.Action {
				return sftpproxy.Stall{When: sftpproxy.After, Release: release, Limit: time.Hour}
			},
			after: true,
		},
		{
			name: "freeze",
			action: func(release <-chan struct{}) sftpproxy.Action {
				return sftpproxy.Freeze{When: sftpproxy.Before, Release: release, Limit: time.Hour}
			},
		},
	}

	orders := []sftpproxy.ReplyOrder{sftpproxy.RequestOrder, sftpproxy.CompletionOrder}
	for _, order := range orders {
		for _, tt := range tests {
			t.Run(order.String()+"/"+tt.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					// Only a channel made inside the bubble counts as durably
					// blocking, so each run makes its own.
					release := make(chan struct{})
					ctx, cancel := context.WithCancel(context.Background())
					fb, backend := startFakeBackend(t, openSSHVersion, "/")
					p := startFaultProxyOn(t, ctx, fb, backend, sftpproxy.Options{
						Faults:     onPath("/a", tt.action(release)),
						ReplyOrder: order,
					})
					start := time.Now()
					p.client.send(t, 1, &sftpwire.Stat{Path: "/a"})
					if tt.after {
						p.backend.reply(t, p.backend.next(t).id, &sftpwire.AttrsReply{})
					}

					synctest.Wait()
					cancel()
					if err := p.result.wait(t); !errors.Is(err, context.Canceled) {
						t.Errorf("Serve = %v, want context.Canceled", err)
					}
					if got := time.Since(start); got != 0 {
						t.Errorf("Serve returned after %v, want at once", got)
					}
					time.Sleep(2 * time.Hour)
					for req := range p.backend.requests {
						t.Errorf("backend received %#v after the session ended", req.packet)
					}
				})
			})
		}
	}
}

func TestDropNeedsTheConnection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fb, backend := startFakeBackend(t, openSSHVersion, "/")
		clientEnd, proxyEnd := net.Pipe()
		t.Cleanup(func() { clientEnd.Close() })
		result := &proxyResult{done: make(chan struct{})}
		go func() {
			defer close(result.done)
			result.err = sftpproxy.Serve(context.Background(), proxyEnd, backend, sftpproxy.Options{
				Faults: onPath("/a", sftpproxy.Drop{When: sftpproxy.Before}),
				Logger: slog.New(slog.DiscardHandler),
			})
		}()
		client := &rawClient{conn: clientEnd, in: bufio.NewReader(clientEnd)}
		client.init(t, 3)

		client.send(t, 1, &sftpwire.Stat{Path: "/a"})
		client.assertClosed(t)
		if err := result.wait(t); err == nil || !strings.Contains(err.Error(), "needs Options.Conn") {
			t.Errorf("Serve = %v, want an error about Options.Conn", err)
		}
		if req, ok := receive(t, fb.requests); ok {
			t.Errorf("backend received %#v", req.packet)
		}
	})
}

// faultProxy is a proxy session with faults between a raw test client and a
// fake backend.
type faultProxy struct {
	client  *rawClient
	backend *fakeBackend
	conn    *fakeConn
	result  *proxyResult
}

// startFaultProxy starts a session in request order with faults over a fake
// connection, logging to logs if it is not nil. The client has already sent
// INIT.
func startFaultProxy(t *testing.T, ctx context.Context, faults func(sftpproxy.Request) sftpproxy.Action, logs *syncBuffer) *faultProxy {
	t.Helper()
	opts := sftpproxy.Options{Faults: faults}
	if logs != nil {
		opts.Logger = slog.New(slog.NewTextHandler(logs, nil))
	}
	fb, backend := startFakeBackend(t, openSSHVersion, "/")
	return startFaultProxyOn(t, ctx, fb, backend, opts)
}

// startFaultProxyOn starts a session with opts and a fake connection between
// a raw test client and fb. A nil opts.Logger discards the logs.
func startFaultProxyOn(t *testing.T, ctx context.Context, fb *fakeBackend, backend net.Conn, opts sftpproxy.Options) *faultProxy {
	t.Helper()
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	clientEnd, proxyEnd := net.Pipe()
	conn := &fakeConn{stream: proxyEnd}
	opts.Conn = conn
	result := &proxyResult{done: make(chan struct{})}
	go func() {
		defer close(result.done)
		result.err = sftpproxy.Serve(ctx, proxyEnd, backend, opts)
	}()
	t.Cleanup(func() {
		clientEnd.Close()
		result.wait(t)
	})
	client := &rawClient{conn: clientEnd, in: bufio.NewReader(clientEnd)}
	client.init(t, 3)
	return &faultProxy{client: client, backend: fb, conn: conn, result: result}
}

// assertNoBackendRequest checks, once every goroutine in the bubble is
// blocked, that the backend has received nothing.
func (p *faultProxy) assertNoBackendRequest(t *testing.T) {
	t.Helper()
	synctest.Wait()
	select {
	case req, ok := <-p.backend.requests:
		if ok {
			t.Fatalf("backend received %#v, want nothing yet", req.packet)
		}
	default:
	}
}

// onPath returns faults that apply action to every request on path.
func onPath(path string, action sftpproxy.Action) func(sftpproxy.Request) sftpproxy.Action {
	return func(r sftpproxy.Request) sftpproxy.Action {
		if r.Path == path {
			return action
		}
		return nil
	}
}

// fakeConn stands in for the client's connection and records what faults do
// to it. Closing or resetting it closes the proxy's end of the client pipe,
// as closing an SSH connection ends its channels.
type fakeConn struct {
	stream net.Conn

	mu  sync.Mutex
	log []string
}

func (c *fakeConn) Close() error { c.record("close"); return c.stream.Close() }
func (c *fakeConn) Reset() error { c.record("reset"); return c.stream.Close() }
func (c *fakeConn) Freeze()      { c.record("freeze") }

func (c *fakeConn) record(event string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.log = append(c.log, event)
}

func (c *fakeConn) events() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.log)
}

// sendTogether writes requests with IDs 1, 2 and so on in a single write, as
// a pipelining client does, so the proxy has them all before it handles the
// first.
func (c *rawClient) sendTogether(t *testing.T, requests ...sftpwire.Packet) {
	t.Helper()
	var b []byte
	for i, p := range requests {
		b = sftpwire.AppendPacket(b, uint32(i+1), p)
	}
	c.write(t, b)
}

// assertReplies checks that the next replies the client receives answer the
// requests with ids, in that order.
func (c *rawClient) assertReplies(t *testing.T, ids ...uint32) {
	t.Helper()
	for _, want := range ids {
		if id, p := c.receiveReply(t); id != want {
			t.Fatalf("received a reply to request %d (%v), want one to %d", id, p.Type(), want)
		}
	}
}

func (c *rawClient) assertStatus(t *testing.T, id uint32, code sftpwire.StatusCode, message string) {
	t.Helper()
	gotID, p := c.receiveReply(t)
	want := sftpwire.StatusReply{Code: code, Message: message}
	if st, ok := p.(*sftpwire.StatusReply); !ok || gotID != id || *st != want {
		t.Errorf("reply = %d %#v, want %d %#v", gotID, p, id, want)
	}
}

func assertPaths(t *testing.T, reqs []backendRequest, paths ...string) {
	t.Helper()
	var got []string
	for _, req := range reqs {
		stat, ok := req.packet.(*sftpwire.Stat)
		if !ok {
			t.Fatalf("backend received %#v, want a STAT", req.packet)
		}
		got = append(got, stat.Path)
	}
	if !slices.Equal(got, paths) {
		t.Errorf("backend received STATs for %v, want %v", got, paths)
	}
}
