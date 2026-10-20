package sftpproxy_test

import (
	"cmp"
	"context"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"sftpit/internal/sftpproxy"
	"sftpit/internal/sftpwire"
)

func TestCompletionOrderDeliversEachReplyWhenReady(t *testing.T) {
	tests := []struct {
		name     string
		requests []sftpwire.Packet
	}{
		{
			name:     "different files",
			requests: []sftpwire.Packet{&sftpwire.Stat{Path: "/slow"}, &sftpwire.Stat{Path: "/other"}},
		},
		{
			// The held reply's operation has already happened, so a later
			// request on the same file need not wait for it.
			name:     "same file",
			requests: []sftpwire.Packet{&sftpwire.Stat{Path: "/slow"}, &sftpwire.LStat{Path: "/slow"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				delay := sftpproxy.Delay{When: sftpproxy.After, Duration: 3 * time.Second}
				p := startCompletionProxy(t, context.Background(), inSequence(delay))
				start := time.Now()
				p.client.sendTogether(t, tt.requests...)

				first, second := p.backend.next(t), p.backend.next(t)
				p.backend.reply(t, first.id, &sftpwire.AttrsReply{})
				p.backend.reply(t, second.id, &sftpwire.AttrsReply{})

				p.client.assertReplies(t, 2)
				if got := time.Since(start); got != 0 {
					t.Errorf("client received the undelayed reply after %v, want at once", got)
				}
				p.client.assertReplies(t, 1)
				if got := time.Since(start); got != 3*time.Second {
					t.Errorf("client received the delayed reply after %v, want 3s", got)
				}
			})
		})
	}
}

func TestCompletionOrderHoldsBackOnlyTheSameFile(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		delay := sftpproxy.Delay{When: sftpproxy.Before, Duration: 3 * time.Second}
		p := startCompletionProxy(t, context.Background(), inSequence(nil, delay))
		p.client.send(t, 1, &sftpwire.Open{Path: "/f", Flags: sftpwire.OpenWrite})
		p.backend.reply(t, p.backend.next(t).id, &sftpwire.HandleReply{Handle: "h"})
		p.client.assertReplies(t, 1)

		start := time.Now()
		p.client.sendTogether(t,
			&sftpwire.Write{Handle: "h", Offset: 0, Data: []byte("held")},
			&sftpwire.Stat{Path: "/g"},
			&sftpwire.Write{Handle: "h", Offset: 4, Data: []byte("next")},
			&sftpwire.Rename{OldPath: "/e", NewPath: "/f"},
			&sftpwire.Stat{Path: "/e"},
			&sftpwire.Close{Handle: "h"},
		)

		other := p.backend.next(t)
		p.assertNoBackendRequest(t)
		p.backend.reply(t, other.id, &sftpwire.AttrsReply{})
		p.client.assertReplies(t, 2)

		var held []sftpwire.Packet
		for range 5 {
			req := p.backend.next(t)
			held = append(held, req.packet)
			p.backend.reply(t, req.id, &sftpwire.StatusReply{Code: sftpwire.StatusOK})
		}
		if got := time.Since(start); got != 3*time.Second {
			t.Errorf("held requests reached the backend after %v, want 3s", got)
		}
		// The STAT on /e and the CLOSE on /f each wait only for the rename,
		// so either may go first.
		want := []sftpwire.PacketType{sftpwire.TypeWrite, sftpwire.TypeWrite, sftpwire.TypeRename}
		if got := packetTypes(held); !slices.Equal(got[:3], want) || !sameElements(got[3:], sftpwire.TypeStat, sftpwire.TypeClose) {
			t.Errorf("backend received %v after the delay, want %v and then a STAT and a CLOSE", got, want)
		}
		if w, ok := held[1].(*sftpwire.Write); !ok || w.Offset != 4 {
			t.Errorf("second request after the delay is %#v, want the write at offset 4", held[1])
		}
		p.client.assertReplies(t, 1, 3, 4)
		if last := []uint32{p.client.nextReplyID(t), p.client.nextReplyID(t)}; !sameElements(last, 5, 6) {
			t.Errorf("last replies answer requests %v, want 5 and 6", last)
		}
	})
}

func TestCompletionOrderDropWaitsForTheBackend(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := startCompletionProxy(t, context.Background(), inSequence(nil, sftpproxy.Drop{When: sftpproxy.Before}))
		p.client.sendTogether(t,
			&sftpwire.Stat{Path: "/first"},
			&sftpwire.Stat{Path: "/a"},
			&sftpwire.Stat{Path: "/last"},
		)

		first := p.backend.next(t)
		p.assertNoBackendRequest(t)
		if got := p.conn.events(); len(got) != 0 {
			t.Fatalf("connection %v while the backend still had a request", got)
		}
		p.backend.reply(t, first.id, &sftpwire.AttrsReply{})
		p.client.assertReplies(t, 1)
		p.client.assertClosed(t)
		if err := p.result.wait(t); err != nil {
			t.Errorf("Serve after a drop = %v, want nil", err)
		}
		if got := p.conn.events(); !slices.Equal(got, []string{"close"}) {
			t.Errorf("connection events = %v, want [close]", got)
		}
		p.assertNoBackendRequest(t)
	})
}

func TestCompletionOrderDropLosesHeldReplies(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		held := sftpproxy.Delay{When: sftpproxy.After, Duration: time.Hour}
		p := startCompletionProxy(t, context.Background(), inSequence(held, sftpproxy.Drop{When: sftpproxy.Before}))
		p.client.sendTogether(t, &sftpwire.Stat{Path: "/held"}, &sftpwire.Stat{Path: "/a"})

		p.backend.reply(t, p.backend.next(t).id, &sftpwire.AttrsReply{})
		p.client.assertClosed(t)
		if got := p.conn.events(); !slices.Equal(got, []string{"close"}) {
			t.Errorf("connection events = %v, want [close]", got)
		}
	})
}

func TestCompletionOrderDropAfterStopsLaterRequests(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := startCompletionProxy(t, context.Background(), inSequence(sftpproxy.Drop{When: sftpproxy.After, Reset: true}))
		p.client.sendTogether(t, &sftpwire.Rename{OldPath: "/a", NewPath: "/b"}, &sftpwire.Stat{Path: "/later"})

		rename := p.backend.next(t)
		p.assertNoBackendRequest(t)
		p.backend.reply(t, rename.id, &sftpwire.StatusReply{Code: sftpwire.StatusOK})
		p.client.assertClosed(t)
		if got := p.conn.events(); !slices.Equal(got, []string{"reset"}) {
			t.Errorf("connection events = %v, want [reset]", got)
		}
		p.assertNoBackendRequest(t)
	})
}

// TestCompletionOrderDropTakesItsTurn checks that a drop waits behind a held
// request on its file, while other files carry on until it happens.
func TestCompletionOrderDropTakesItsTurn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		delay := sftpproxy.Delay{When: sftpproxy.Before, Duration: 2 * time.Second}
		p := startCompletionProxy(t, context.Background(), inSequence(delay, sftpproxy.Drop{When: sftpproxy.Before}))
		start := time.Now()
		p.client.sendTogether(t,
			&sftpwire.Stat{Path: "/a"},
			&sftpwire.Remove{Path: "/a"},
			&sftpwire.Stat{Path: "/g"},
		)

		other := p.backend.next(t)
		p.backend.reply(t, other.id, &sftpwire.AttrsReply{})
		p.client.assertReplies(t, 3)

		stat := p.backend.next(t)
		if got := time.Since(start); got != 2*time.Second {
			t.Errorf("held request reached the backend after %v, want 2s", got)
		}
		assertPaths(t, []backendRequest{stat}, "/a")
		p.assertNoBackendRequest(t)
		if got := p.conn.events(); len(got) != 0 {
			t.Fatalf("connection %v while the backend still had a request", got)
		}
		p.backend.reply(t, stat.id, &sftpwire.AttrsReply{})
		p.client.assertReplies(t, 1)
		p.client.assertClosed(t)
	})
}

// TestCompletionOrderBoundsRequestsInFlight checks that a session stops
// taking requests while 256 await their replies, as it does in request
// order, so the replies it holds stay bounded.
func TestCompletionOrderBoundsRequestsInFlight(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const limit = 256
		p := startCompletionProxy(t, context.Background(), nil)
		requests := make([]sftpwire.Packet, limit+1)
		for i := range requests {
			requests[i] = &sftpwire.Stat{Path: "/a"}
		}
		go p.client.sendTogether(t, requests...)

		var received []backendRequest
		collect := func() {
			synctest.Wait()
			for {
				select {
				case req := <-p.backend.requests:
					received = append(received, req)
				default:
					return
				}
			}
		}
		// The fake backend queues only a few requests, so take them as they
		// come until the proxy stops sending.
		for range limit {
			collect()
		}
		if len(received) != limit {
			t.Fatalf("backend received %d requests, want %d", len(received), limit)
		}

		p.backend.reply(t, received[0].id, &sftpwire.AttrsReply{})
		p.client.assertReplies(t, 1)
		collect()
		if len(received) != limit+1 {
			t.Errorf("backend received %d requests after one reply, want %d", len(received), limit+1)
		}
	})
}

// startCompletionProxy starts a session in completion order with faults
// over a fake connection. The client has already sent INIT.
func startCompletionProxy(t *testing.T, ctx context.Context, faults func(sftpproxy.Request) sftpproxy.Action) *faultProxy {
	t.Helper()
	fb, backend := startFakeBackend(t, openSSHVersion, "/")
	return startFaultProxyOn(t, ctx, fb, backend, sftpproxy.Options{Faults: faults, ReplyOrder: sftpproxy.CompletionOrder})
}

// inSequence returns faults that apply actions to requests in the order
// they arrive: the first action to the first request, and so on. A nil
// action, or a request beyond the last, gets no fault.
func inSequence(actions ...sftpproxy.Action) func(sftpproxy.Request) sftpproxy.Action {
	var n int
	return func(sftpproxy.Request) sftpproxy.Action {
		n++
		if n > len(actions) {
			return nil
		}
		return actions[n-1]
	}
}

func packetTypes(packets []sftpwire.Packet) []sftpwire.PacketType {
	var types []sftpwire.PacketType
	for _, p := range packets {
		types = append(types, p.Type())
	}
	return types
}

func (c *rawClient) nextReplyID(t *testing.T) uint32 {
	t.Helper()
	id, _ := c.receiveReply(t)
	return id
}

func sameElements[T cmp.Ordered](got []T, want ...T) bool {
	return slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want)))
}
