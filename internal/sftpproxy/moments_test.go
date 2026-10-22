package sftpproxy_test

import (
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

func TestTimersFireAtTheirMoment(t *testing.T) {
	tests := []struct {
		name   string
		action sftpproxy.Action
		events []string
		ended  time.Duration
		log    string
	}{
		{"close", sftpproxy.Drop{}, []string{"close"}, 2 * time.Second, `level=INFO msg="injected fault" fault=close_connection when=timer mode=fin`},
		{"reset", sftpproxy.Drop{Reset: true}, []string{"reset"}, 2 * time.Second, `level=INFO msg="injected fault" fault=close_connection when=timer mode=rst`},
		{"freeze", sftpproxy.Freeze{Limit: time.Second}, []string{"freeze", "close"}, 3 * time.Second, `level=INFO msg="injected fault" fault=freeze_connection when=timer limit=1s`},
		{"end the session", sftpproxy.EndSession{}, nil, 2 * time.Second, `level=INFO msg="injected fault" fault=close_subsystem when=timer`},
	}
	for _, tt := range tests {
		for _, order := range replyOrders {
			t.Run(tt.name+"/"+order.String(), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					var logs syncBuffer
					start := time.Now()
					p, _ := startProxyOnFake(t, sftpproxy.Options{
						Timers:     []sftpproxy.Timer{{At: start.Add(2 * time.Second), Action: tt.action}},
						ReplyOrder: order,
						Logger:     slog.New(slog.NewTextHandler(&logs, nil)),
					})
					p.client.assertClosed(t)
					if got := time.Since(start); got != tt.ended {
						t.Errorf("the session ended after %v, want %v", got, tt.ended)
					}
					if err := p.result.wait(t); err != nil {
						t.Errorf("Serve = %v, want nil", err)
					}
					if got := p.conn.events(); !slices.Equal(got, tt.events) {
						t.Errorf("connection events = %v, want %v", got, tt.events)
					}
					if !strings.Contains(logs.String(), tt.log) {
						t.Errorf("logs lack %s:\n%s", tt.log, logs.String())
					}
				})
			})
		}
	}
}

func TestATimerWaitsForTheBackendButWritesNoMoreReplies(t *testing.T) {
	for _, order := range replyOrders {
		t.Run(order.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var snaps snapshots
				start := time.Now()
				p, fb := startProxyOnFake(t, sftpproxy.Options{
					Faults:     inSequence(sftpproxy.Fail{When: sftpproxy.After, Status: sftpwire.StatusFailure}),
					Timers:     []sftpproxy.Timer{{At: start.Add(2 * time.Second), Action: sftpproxy.Drop{}}},
					ReplyOrder: order,
					Snapshot:   snaps.take,
				})
				// A faulted upload is still open, and a write is with the
				// backend, when the moment comes.
				p.client.send(t, 1, &sftpwire.Open{Path: "/f", Flags: sftpwire.OpenWrite | sftpwire.OpenCreate})
				fb.reply(t, fb.next(t).id, &sftpwire.HandleReply{Handle: "h"})
				p.client.assertStatus(t, 1, sftpwire.StatusFailure, "Failure")
				p.client.send(t, 2, write("h", 0, 10))
				pending := fb.next(t)
				time.Sleep(3 * time.Second)

				p.client.send(t, 3, &sftpwire.Stat{Path: "/later"})
				fb.assertNoRequest(t)
				if got := p.conn.events(); len(got) != 0 {
					t.Fatalf("connection %v before the backend answered", got)
				}
				fb.reply(t, pending.id, status(sftpwire.StatusOK))
				p.client.assertClosed(t)
				if got := p.conn.events(); !slices.Equal(got, []string{"close"}) {
					t.Errorf("connection events = %v, want [close]", got)
				}
				if got := snaps.taken(); !slices.Equal(got, []string{"/f"}) {
					t.Errorf("snapshots = %v, want the faulted upload's", got)
				}
			})
		})
	}
}

func TestAPastTimerFiresAsTheSessionStarts(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		p, _ := startProxyOnFake(t, sftpproxy.Options{Timers: []sftpproxy.Timer{{At: start.Add(-time.Hour), Action: sftpproxy.Drop{Reset: true}}}})
		p.client.assertClosed(t)
		if got := time.Since(start); got != 0 {
			t.Errorf("the session ended after %v, want at once", got)
		}
		if got := p.conn.events(); !slices.Equal(got, []string{"reset"}) {
			t.Errorf("connection events = %v, want [reset]", got)
		}
	})
}

func TestADeclinedMomentChangesNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex
		var asked []time.Duration
		start := time.Now()
		reserve := func() bool {
			mu.Lock()
			defer mu.Unlock()
			asked = append(asked, time.Since(start))
			return false
		}
		timed := sftpproxy.Timed{After: time.Second, Action: sftpproxy.Drop{}, Reserve: reserve}
		p, fb := startProxyOnFake(t, sftpproxy.Options{
			Faults: func(r sftpproxy.Request) sftpproxy.Action {
				if _, ok := r.Packet.(*sftpwire.Open); ok {
					return timed
				}
				return nil
			},
			Timers: []sftpproxy.Timer{{At: start.Add(2 * time.Second), Action: sftpproxy.Drop{}, Reserve: reserve}},
		})
		openForUpload(t, p, fb, "h")
		time.Sleep(3 * time.Second)
		p.client.send(t, 2, &sftpwire.Stat{Path: "/f"})
		fb.reply(t, fb.next(t).id, &sftpwire.AttrsReply{})
		p.client.assertReplies(t, 2)
		if got := p.conn.events(); len(got) != 0 {
			t.Errorf("connection events = %v after the moments were declined", got)
		}
		mu.Lock()
		defer mu.Unlock()
		if want := []time.Duration{time.Second, 2 * time.Second}; !slices.Equal(asked, want) {
			t.Errorf("Reserve was called after %v, want %v", asked, want)
		}
	})
}

func TestTimedFaultsCountFromTheHandlesOpen(t *testing.T) {
	for _, order := range replyOrders {
		t.Run(order.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var logs syncBuffer
				var snaps snapshots
				p, fb := startProxyOnFake(t, sftpproxy.Options{
					Faults:     onOpen("/f", sftpproxy.Timed{After: 2 * time.Second, Action: sftpproxy.Drop{Reset: true}}),
					ReplyOrder: order,
					Snapshot:   snaps.take,
					Logger:     slog.New(slog.NewTextHandler(&logs, nil)),
				})
				start := time.Now()
				p.client.send(t, 1, &sftpwire.Open{Path: "/f", Flags: sftpwire.OpenWrite | sftpwire.OpenCreate})
				open := fb.next(t)
				time.Sleep(time.Second)
				fb.reply(t, open.id, &sftpwire.HandleReply{Handle: "h"})
				p.client.assertReplies(t, 1)
				p.client.send(t, 2, write("h", 0, 10))
				fb.reply(t, fb.next(t).id, status(sftpwire.StatusOK))
				p.client.assertReplies(t, 2)

				p.client.assertClosed(t)
				// The snapshot takes a second of its own.
				if got, want := time.Since(start), 3*time.Second+snapshotTime; got != want {
					t.Errorf("the connection was reset after %v, want %v: 2s after the handle opened, and the snapshot", got, want)
				}
				if got := p.conn.events(); !slices.Equal(got, []string{"reset"}) {
					t.Errorf("connection events = %v, want [reset]", got)
				}
				assertSnapshotsLogged(t, logs.String(), snapshotLog("/f", "fault"))
				if want := `level=INFO msg="injected fault" path=/f fault=close_connection when=timer mode=rst`; !strings.Contains(logs.String(), want) {
					t.Errorf("logs lack %s:\n%s", want, logs.String())
				}
			})
		})
	}
}

func TestClosingTheHandleStopsItsTimedFault(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs syncBuffer
		var snaps snapshots
		p, fb := startProxyOnFake(t, sftpproxy.Options{
			Faults:   onOpen("/f", sftpproxy.Timed{After: 2 * time.Second, Action: sftpproxy.Drop{}}),
			Snapshot: snaps.take,
			Logger:   slog.New(slog.NewTextHandler(&logs, nil)),
		})
		openForUpload(t, p, fb, "h")
		time.Sleep(time.Second)
		p.client.send(t, 2, &sftpwire.Close{Handle: "h"})
		fb.reply(t, fb.next(t).id, status(sftpwire.StatusOK))
		p.client.assertReplies(t, 2)

		time.Sleep(time.Hour)
		p.client.send(t, 3, &sftpwire.Stat{Path: "/f"})
		fb.reply(t, fb.next(t).id, &sftpwire.AttrsReply{})
		p.client.assertReplies(t, 3)
		if got := p.conn.events(); len(got) != 0 {
			t.Errorf("connection events = %v after the handle closed", got)
		}
		// The handle was never faulted, so its file needs no evidence.
		if got := snaps.taken(); len(got) != 0 || strings.Contains(logs.String(), "injected fault") {
			t.Errorf("snapshots %v and logs\n%s\nwant neither for a moment that never came", got, logs.String())
		}
	})
}

func TestEndSessionClosesTheSessionAfterEarlierReplies(t *testing.T) {
	for _, when := range []sftpproxy.When{sftpproxy.Before, sftpproxy.After} {
		t.Run(when.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p, fb := startProxyOnFake(t, sftpproxy.Options{Faults: onPath("/a", sftpproxy.EndSession{When: when})})
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
				fb.reply(t, first.id, &sftpwire.AttrsReply{})
				p.client.assertReplies(t, 1)
				p.client.assertClosed(t)
				if err := p.result.wait(t); err != nil {
					t.Errorf("Serve = %v, want nil", err)
				}
				if got := p.conn.events(); len(got) != 0 {
					t.Errorf("connection events = %v, want the connection left alone", got)
				}
			})
		})
	}
}

func TestUnusableTimersEndTheSession(t *testing.T) {
	tests := []struct {
		name   string
		action sftpproxy.Action
		conn   bool
		err    string
	}{
		{"a failure", sftpproxy.Fail{Status: sftpwire.StatusFailure}, true, "a fault at a moment must be a Drop, Freeze, EndSession or ListenerDown, not sftpproxy.Fail"},
		{"a drop without the connection", sftpproxy.Drop{}, false, "a sftpproxy.Drop fault needs Options.Conn"},
		{"a listener down without the listener", sftpproxy.ListenerDown{Duration: time.Second}, true, "a ListenerDown fault needs Options.Listener"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				_, backend := startFakeBackend(t, openSSHVersion, "/")
				clientEnd, proxyEnd := net.Pipe()
				t.Cleanup(func() { clientEnd.Close() })
				opts := sftpproxy.Options{
					Timers: []sftpproxy.Timer{{At: time.Now().Add(time.Hour), Action: tt.action}},
					Logger: slog.New(slog.DiscardHandler),
				}
				if tt.conn {
					opts.Conn = &fakeConn{stream: proxyEnd}
				}
				result := serveInBackground(t.Context(), proxyEnd, backend, opts)
				newRawClient(clientEnd).init(t, 3)
				if err := result.wait(t); err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Errorf("Serve = %v, want an error containing %q", err, tt.err)
				}
			})
		})
	}
}

// onOpen returns faults that apply action to each OPEN of path.
func onOpen(path string, action sftpproxy.Action) func(sftpproxy.Request) sftpproxy.Action {
	return func(r sftpproxy.Request) sftpproxy.Action {
		if _, ok := r.Packet.(*sftpwire.Open); ok && r.Path == path {
			return action
		}
		return nil
	}
}
