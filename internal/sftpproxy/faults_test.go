package sftpproxy_test

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

func TestDelayBeforeHoldsTheRequestAndEveryLaterOne(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, fb := startProxyOnFake(t, sftpproxy.Options{Faults: onPath("/slow", sftpproxy.Delay{When: sftpproxy.Before, Duration: 3 * time.Second})})
		start := time.Now()
		p.client.sendTogether(t, &sftpwire.Stat{Path: "/slow"}, &sftpwire.Stat{Path: "/other"})

		fb.assertNoRequest(t)
		slow := fb.next(t)
		if got := time.Since(start); got != 3*time.Second {
			t.Errorf("backend received the delayed request after %v, want 3s", got)
		}
		other := fb.next(t)
		assertPaths(t, []backendRequest{slow, other}, "/slow", "/other")

		fb.reply(t, slow.id, &sftpwire.AttrsReply{})
		fb.reply(t, other.id, &sftpwire.AttrsReply{})
		p.client.assertReplies(t, 1, 2)
	})
}

func TestDelayAfterHoldsTheReplyAndEveryLaterOne(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, fb := startProxyOnFake(t, sftpproxy.Options{Faults: onPath("/slow", sftpproxy.Delay{When: sftpproxy.After, Duration: 3 * time.Second})})
		start := time.Now()
		p.client.sendTogether(t, &sftpwire.Stat{Path: "/slow"}, &sftpwire.Stat{Path: "/other"})

		slow, other := fb.next(t), fb.next(t)
		assertPaths(t, []backendRequest{slow, other}, "/slow", "/other")
		fb.reply(t, slow.id, &sftpwire.AttrsReply{})
		fb.reply(t, other.id, &sftpwire.AttrsReply{})

		p.client.assertReplies(t, 1)
		if got := time.Since(start); got != 3*time.Second {
			t.Errorf("client received the delayed reply after %v, want 3s", got)
		}
		p.client.assertReplies(t, 2)
	})
}

func TestADelayEndsEarlyWhenReleased(t *testing.T) {
	tests := []struct {
		name    string
		when    sftpproxy.When
		release bool
		want    time.Duration
	}{
		{name: "before, released", when: sftpproxy.Before, release: true, want: time.Second},
		{name: "before, run its course", when: sftpproxy.Before, want: 3 * time.Second},
		{name: "after, released", when: sftpproxy.After, release: true, want: time.Second},
		{name: "after, run its course", when: sftpproxy.After, want: 3 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var logs syncBuffer
				release := make(chan struct{})
				p, fb := startProxyOnFake(t, sftpproxy.Options{
					Faults: onPath("/a", sftpproxy.Delay{When: tt.when, Duration: 3 * time.Second, Release: release}),
					Logger: slog.New(slog.NewTextHandler(&logs, nil)),
				})
				start := time.Now()
				p.client.send(t, 1, &sftpwire.Stat{Path: "/a"})
				if tt.release {
					time.AfterFunc(time.Second, func() { close(release) })
				}

				fb.reply(t, fb.next(t).id, &sftpwire.AttrsReply{})
				p.client.assertReplies(t, 1)
				if got := time.Since(start); got != tt.want {
					t.Errorf("the delay ended after %v, want %v", got, tt.want)
				}
				released := strings.Contains(logs.String(), `msg="fault released"`)
				if released != tt.release || strings.Contains(logs.String(), "ended at its limit") {
					t.Errorf("logs, for a delay released %v:\n%s", tt.release, logs.String())
				}
			})
		})
	}
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
				p, fb := startProxyOnFake(t, sftpproxy.Options{
					Faults: onPath("/a", stall),
					Logger: slog.New(slog.NewTextHandler(&logs, nil)),
				})
				start := time.Now()
				p.client.send(t, 1, &sftpwire.Stat{Path: "/a"})
				if tt.release {
					time.AfterFunc(time.Second, func() { close(release) })
				}

				fb.reply(t, fb.next(t).id, &sftpwire.AttrsReply{})
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
		p, fb := startProxyOnFake(t, sftpproxy.Options{
			Faults: onPath("/a", sftpproxy.Fail{When: sftpproxy.Before, Status: sftpwire.StatusPermissionDenied}),
			Logger: slog.New(slog.NewTextHandler(&logs, nil)),
		})
		p.client.sendTogether(t, &sftpwire.Rename{OldPath: "/a", NewPath: "/b"}, &sftpwire.Stat{Path: "/c"})

		stat := fb.next(t)
		assertPaths(t, []backendRequest{stat}, "/c")
		fb.reply(t, stat.id, &sftpwire.AttrsReply{})
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
		p, fb := startProxyOnFake(t, sftpproxy.Options{Faults: onPath("/a", sftpproxy.Fail{When: sftpproxy.After, Status: sftpwire.StatusFailure})})
		p.client.send(t, 1, &sftpwire.Rename{OldPath: "/a", NewPath: "/b"})

		rename := fb.next(t)
		if _, ok := rename.packet.(*sftpwire.Rename); !ok {
			t.Fatalf("backend received %#v, want the rename", rename.packet)
		}
		fb.reply(t, rename.id, &sftpwire.StatusReply{Code: sftpwire.StatusOK})
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
		p, fb := startProxyOnFake(t, sftpproxy.Options{Faults: faults})
		p.client.send(t, 1, &sftpwire.Open{Path: "/a", Flags: sftpwire.OpenRead})
		fb.reply(t, fb.next(t).id, &sftpwire.HandleReply{Handle: "h"})
		p.client.assertReplies(t, 1)

		p.client.send(t, 2, &sftpwire.Close{Handle: "h"})
		p.client.assertStatus(t, 2, sftpwire.StatusFailure, "Failure")
		p.client.send(t, 3, &sftpwire.Read{Handle: "h", Length: 10})

		read := fb.next(t)
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
		p := startProxy(t, backend, sftpproxy.Options{Faults: faults})
		p.client.init(t, 3)
		p.client.send(t, 1, &sftpwire.Rename{OldPath: "a.part", NewPath: "../q/a"})
		fb.next(t)

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
				p, fb := startProxyOnFake(t, sftpproxy.Options{Faults: onPath("/a", tt.drop)})
				p.client.sendTogether(t,
					&sftpwire.Stat{Path: "/first"},
					&sftpwire.Rename{OldPath: "/a", NewPath: "/b"},
					&sftpwire.Stat{Path: "/last"},
				)

				first := fb.next(t)
				if tt.drop.When == sftpproxy.After {
					rename := fb.next(t)
					fb.reply(t, rename.id, &sftpwire.StatusReply{Code: sftpwire.StatusOK})
				}
				fb.assertNoRequest(t)
				if got := p.conn.events(); len(got) != 0 {
					t.Fatalf("connection %v before the earlier reply was written", got)
				}

				fb.reply(t, first.id, &sftpwire.AttrsReply{})
				p.client.assertReplies(t, 1)
				p.client.assertClosed(t)
				if err := p.result.wait(t); err != nil {
					t.Errorf("Serve after a drop = %v, want nil", err)
				}
				if got := p.conn.events(); !slices.Equal(got, []string{tt.event}) {
					t.Errorf("connection events = %v, want [%s]", got, tt.event)
				}
				fb.assertNoRequest(t)
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
				p, fb := startProxyOnFake(t, sftpproxy.Options{Faults: onPath("/a", freeze)})
				start := time.Now()
				p.client.send(t, 1, &sftpwire.Rename{OldPath: "/a", NewPath: "/b"})
				fb.reply(t, fb.next(t).id, &sftpwire.StatusReply{Code: sftpwire.StatusOK})

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
					p, fb := startProxyOnFake(t, sftpproxy.Options{
						Faults:     onPath("/a", tt.action(release)),
						ReplyOrder: order,
					})
					start := time.Now()
					p.client.send(t, 1, &sftpwire.Stat{Path: "/a"})
					if tt.after {
						fb.reply(t, fb.next(t).id, &sftpwire.AttrsReply{})
					}

					synctest.Wait()
					p.cancel()
					if err := p.result.wait(t); !errors.Is(err, context.Canceled) {
						t.Errorf("Serve = %v, want context.Canceled", err)
					}
					if got := time.Since(start); got != 0 {
						t.Errorf("Serve returned after %v, want at once", got)
					}
					time.Sleep(2 * time.Hour)
					for req := range fb.requests {
						t.Errorf("backend received %#v after the session ended", req.packet)
					}
				})
			})
		}
	}
}

// TestUnusableFaultsEndTheSession checks that a fault the session cannot
// apply ends it with an error before the request reaches the backend. The
// session has no Options.Conn.
func TestUnusableFaultsEndTheSession(t *testing.T) {
	open := &sftpwire.Open{Path: "/a", Flags: sftpwire.OpenWrite}
	fail := sftpproxy.Fail{Status: sftpwire.StatusFailure}
	tests := []struct {
		name    string
		request sftpwire.Packet
		action  sftpproxy.Action
		err     string
	}{
		{
			name:    "drop without the connection",
			request: &sftpwire.Stat{Path: "/a"},
			action:  sftpproxy.Drop{When: sftpproxy.Before},
			err:     "a sftpproxy.Drop fault needs Options.Conn",
		},
		{
			name:    "listener down without the listener",
			request: &sftpwire.Stat{Path: "/a"},
			action:  sftpproxy.ListenerDown{When: sftpproxy.Before, Duration: time.Second},
			err:     "a ListenerDown fault needs Options.Listener",
		},
		{
			name:    "partial upload on a request other than OPEN",
			request: &sftpwire.Stat{Path: "/a"},
			action:  sftpproxy.PartialUpload{Cutoff: 100, Result: fail},
			err:     "a PartialUpload fault is for OPEN, not SSH_FXP_STAT",
		},
		{
			name:    "partial upload without a result",
			request: open,
			action:  sftpproxy.PartialUpload{Cutoff: 100},
			err:     "a PartialUpload result must be a Fail, Drop or Freeze, not <nil>",
		},
		{
			name:    "partial upload ending in a delay",
			request: open,
			action:  sftpproxy.PartialUpload{Cutoff: 100, Result: sftpproxy.Delay{Duration: time.Second}},
			err:     "a PartialUpload result must be a Fail, Drop or Freeze, not sftpproxy.Delay",
		},
		{
			name:    "partial upload ending in a drop without the connection",
			request: open,
			action:  sftpproxy.PartialUpload{Cutoff: 100, Result: sftpproxy.Drop{}},
			err:     "a sftpproxy.Drop fault needs Options.Conn",
		},
		{
			name:    "corrupt download on a request other than OPEN",
			request: &sftpwire.Stat{Path: "/a"},
			action:  sftpproxy.CorruptDownload{Corruption: sftpproxy.Truncate},
			err:     "a CorruptDownload fault is for OPEN, not SSH_FXP_STAT",
		},
		{
			name:    "omitting nothing",
			request: open,
			action:  sftpproxy.CorruptDownload{Corruption: sftpproxy.OmitRange, Offset: 100},
			err:     "a CorruptDownload omit_range of 0 bytes at 100 does not fit a file",
		},
		{
			name:    "flipping bytes beyond any file",
			request: open,
			action:  sftpproxy.CorruptDownload{Corruption: sftpproxy.FlipBytes, Offset: 1 << 63, Length: 1 << 63},
			err:     "a CorruptDownload flip_bytes of 9223372036854775808 bytes at 9223372036854775808 does not fit a file",
		},
		{
			name:    "unknown corruption",
			request: open,
			action:  sftpproxy.CorruptDownload{Corruption: 7},
			err:     "unknown CorruptDownload corruption Corruption(7)",
		},
		{
			name:    "timed fault on a request other than OPEN",
			request: &sftpwire.Stat{Path: "/a"},
			action:  sftpproxy.Timed{After: time.Second, Action: sftpproxy.EndSession{}},
			err:     "a Timed fault is for OPEN, not SSH_FXP_STAT",
		},
		{
			name:    "timed failure",
			request: open,
			action:  sftpproxy.Timed{After: time.Second, Action: fail},
			err:     "a fault at a moment must be a Drop, Freeze, EndSession or ListenerDown, not sftpproxy.Fail",
		},
		{
			name:    "timed drop without the connection",
			request: open,
			action:  sftpproxy.Timed{After: time.Second, Action: sftpproxy.Drop{}},
			err:     "a sftpproxy.Drop fault needs Options.Conn",
		},
		{
			name:    "wrong size on a request other than a stat",
			request: open,
			action:  sftpproxy.WrongSize{Size: 1},
			err:     "a WrongSize fault is for STAT, LSTAT, FSTAT or a READDIR entry, not SSH_FXP_OPEN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				fb, backend := startFakeBackend(t, openSSHVersion, "/")
				clientEnd, proxyEnd := net.Pipe()
				t.Cleanup(func() { clientEnd.Close() })
				result := serveInBackground(t.Context(), proxyEnd, backend, sftpproxy.Options{
					Faults: onPath("/a", tt.action),
					Logger: slog.New(slog.DiscardHandler),
				})
				client := newRawClient(clientEnd)
				client.init(t, 3)

				client.send(t, 1, tt.request)
				client.assertClosed(t)
				if err := result.wait(t); err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Errorf("Serve = %v, want an error containing %q", err, tt.err)
				}
				if req, ok := receive(t, fb.requests); ok {
					t.Errorf("backend received %#v", req.packet)
				}
			})
		})
	}
}
