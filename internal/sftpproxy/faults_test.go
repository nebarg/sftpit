package sftpproxy_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"reflect"
	"slices"
	"strings"
	"sync"
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
					Logger: logs.logger(),
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
					Logger: logs.logger(),
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
				logs.assertLogged(t, wantLog)
			})
		})
	}
}

func TestReleasedEndsTheStallsAndFreezesInProgress(t *testing.T) {
	tests := []struct {
		name   string
		action sftpproxy.Action
		// early is set if the release comes before the request, when
		// Released has a fresh channel for it.
		early bool
		want  time.Duration
		log   string
	}{
		{name: "a stall before", action: sftpproxy.Stall{When: sftpproxy.Before, Limit: 4 * time.Second}, want: time.Second, log: `msg="fault released"`},
		{name: "a stall after", action: sftpproxy.Stall{When: sftpproxy.After, Limit: 4 * time.Second}, want: time.Second, log: `msg="fault released"`},
		{name: "a stall that begins after the release", action: sftpproxy.Stall{When: sftpproxy.Before, Limit: 4 * time.Second}, early: true, want: 4 * time.Second, log: `msg="fault ended at its limit"`},
		{name: "a delay", action: sftpproxy.Delay{When: sftpproxy.Before, Duration: 3 * time.Second}, want: 3 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var logs syncBuffer
				var mu sync.Mutex
				current := make(chan struct{})
				release := func() {
					mu.Lock()
					defer mu.Unlock()
					close(current)
					current = make(chan struct{})
				}
				p, fb := startProxyOnFake(t, sftpproxy.Options{
					Faults: onPath("/a", tt.action),
					Released: func() <-chan struct{} {
						mu.Lock()
						defer mu.Unlock()
						return current
					},
					Logger: logs.logger(),
				})
				if tt.early {
					release()
				}
				start := time.Now()
				p.client.send(t, 1, &sftpwire.Stat{Path: "/a"})
				if !tt.early {
					time.AfterFunc(time.Second, release)
				}
				fb.reply(t, fb.next(t).id, &sftpwire.AttrsReply{})
				p.client.assertReplies(t, 1)
				if got := time.Since(start); got != tt.want {
					t.Errorf("the reply came after %v, want %v", got, tt.want)
				}
				if tt.log != "" {
					logs.assertLogged(t, tt.log)
				}
			})
		})
	}
}

func TestReleasedClosesAFrozenConnection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		released := make(chan struct{})
		p, _ := startProxyOnFake(t, sftpproxy.Options{
			Faults:   onPath("/a", sftpproxy.Freeze{When: sftpproxy.Before, Limit: time.Minute}),
			Released: func() <-chan struct{} { return released },
		})
		start := time.Now()
		p.client.send(t, 1, &sftpwire.Stat{Path: "/a"})
		time.AfterFunc(time.Second, func() { close(released) })
		p.client.assertClosed(t)
		if got := time.Since(start); got != time.Second {
			t.Errorf("the frozen connection closed after %v, want 1s", got)
		}
		if got := p.conn.events(); !slices.Equal(got, []string{"freeze", "close"}) {
			t.Errorf("connection events = %v, want it frozen, then closed", got)
		}
	})
}

func TestFailBeforeAnswersWithoutTheBackend(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs syncBuffer
		p, fb := startProxyOnFake(t, sftpproxy.Options{
			Faults: onPath("/a", sftpproxy.Fail{When: sftpproxy.Before, Status: sftpwire.StatusPermissionDenied}),
			Logger: logs.logger(),
		})
		p.client.sendTogether(t, &sftpwire.Rename{OldPath: "/a", NewPath: "/b"}, &sftpwire.Stat{Path: "/c"})

		stat := fb.next(t)
		assertPaths(t, []backendRequest{stat}, "/c")
		fb.reply(t, stat.id, &sftpwire.AttrsReply{})
		p.client.assertStatus(t, 1, sftpwire.StatusPermissionDenied, "Permission denied")
		p.client.assertReplies(t, 2)

		want := "msg=\"injected fault\" request=SSH_FXP_RENAME path=/a target=/b fault=fail when=before status=SSH_FX_PERMISSION_DENIED"
		logs.assertLogged(t, want)
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

// TestSessionEndingFaultsComeAfterEarlierRepliesAndBeforeLaterRequests
// checks that a fault that ends the session, before or after the backend
// acts, ends it where the request's reply would be: every earlier reply is
// written first, and no later request reaches the backend.
func TestSessionEndingFaultsComeAfterEarlierRepliesAndBeforeLaterRequests(t *testing.T) {
	tests := []struct {
		name   string
		action func(sftpproxy.When) sftpproxy.Action
		events []string
		// log, if set, is a format for part of what the fault logs, given
		// its When.
		log string
	}{
		{
			name:   "FIN",
			action: func(w sftpproxy.When) sftpproxy.Action { return sftpproxy.Drop{When: w} },
			events: []string{"close"},
		},
		{
			name:   "RST",
			action: func(w sftpproxy.When) sftpproxy.Action { return sftpproxy.Drop{When: w, Reset: true} },
			events: []string{"reset"},
		},
		{
			name:   "end session",
			action: func(w sftpproxy.When) sftpproxy.Action { return sftpproxy.EndSession{When: w} },
		},
		{
			name: "listener down closing every connection",
			action: func(w sftpproxy.When) sftpproxy.Action {
				return sftpproxy.ListenerDown{When: w, Duration: 5 * time.Second, CloseExisting: true}
			},
			events: []string{"down 5s, closing every connection"},
			log:    `msg="injected fault" request=SSH_FXP_RENAME path=/a target=/b fault=listener_down when=%v duration=5s close_existing=true`,
		},
	}
	for _, tt := range tests {
		for _, when := range []sftpproxy.When{sftpproxy.Before, sftpproxy.After} {
			t.Run(tt.name+"/"+when.String(), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					var logs syncBuffer
					p, fb := startProxyOnFake(t, sftpproxy.Options{
						Faults: onPath("/a", tt.action(when)),
						Logger: logs.logger(),
					})
					p.client.sendTogether(t,
						&sftpwire.Stat{Path: "/first"},
						&sftpwire.Rename{OldPath: "/a", NewPath: "/b"},
						&sftpwire.Stat{Path: "/last"},
					)

					first := fb.next(t)
					if when == sftpproxy.After {
						fb.reply(t, fb.next(t).id, status(sftpwire.StatusOK))
					}
					fb.assertNoRequest(t)
					if got := p.conn.events(); len(got) != 0 {
						t.Fatalf("connection events %v before the earlier reply was written", got)
					}

					fb.reply(t, first.id, &sftpwire.AttrsReply{})
					p.client.assertReplies(t, 1)
					p.client.assertClosed(t)
					if err := p.result.wait(t); err != nil {
						t.Errorf("Serve = %v, want nil", err)
					}
					if got := p.conn.events(); !slices.Equal(got, tt.events) {
						t.Errorf("connection events = %v, want %v", got, tt.events)
					}
					fb.assertNoRequest(t)
					if tt.log != "" {
						logs.assertLogged(t, fmt.Sprintf(tt.log, when))
					}
				})
			})
		}
	}
}

func TestFreezeClosesAtReleaseOrLimit(t *testing.T) {
	tests := []struct {
		name    string
		release bool
		want    time.Duration
	}{
		{name: "released", release: true, want: time.Second},
		{name: "at the limit", want: 4 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
				if tt.release {
					time.Sleep(tt.want)
					close(releaseCh)
				}
				p.client.assertClosed(t)
				if got := time.Since(start); got != tt.want {
					t.Errorf("connection closed after %v, want %v", got, tt.want)
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

	for _, order := range replyOrders {
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
// session has neither Options.Conn nor Options.Listener.
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
				if req, ok := fb.receive(t); ok {
					t.Errorf("backend received %#v", req.packet)
				}
			})
		})
	}
}
