package sftpproxy_test

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

func TestPartialDownloadShortensTheReadThatCrossesItsCutoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs syncBuffer
		var snaps snapshots
		p, fb := startProxyOnFake(t, sftpproxy.Options{
			Faults:   inSequence(sftpproxy.PartialDownload{Cutoff: 100, Result: sftpproxy.Fail{Status: sftpwire.StatusFailure}}),
			Snapshot: snaps.take,
			Logger:   logs.logger(),
		})
		openForDownload(t, p, fb)
		data := bytes.Repeat([]byte{'x'}, 200)

		// Below the cutoff, a read goes through.
		p.client.send(t, 2, &sftpwire.Read{Handle: "h", Offset: 0, Length: 50})
		req := fb.next(t)
		if r := req.packet.(*sftpwire.Read); r.Offset != 0 || r.Length != 50 {
			t.Fatalf("backend received a read of %d at %d, want 50 at 0", r.Length, r.Offset)
		}
		fb.reply(t, req.id, &sftpwire.DataReply{Data: data[:50]})
		p.client.assertReplies(t, 2)

		// Across it, the read reaches the backend shortened to end there.
		p.client.send(t, 3, &sftpwire.Read{Handle: "h", Offset: 50, Length: 100})
		req = fb.next(t)
		if r := req.packet.(*sftpwire.Read); r.Offset != 50 || r.Length != 50 {
			t.Fatalf("backend received a read of %d at %d, want 50 at 50", r.Length, r.Offset)
		}
		fb.reply(t, req.id, &sftpwire.DataReply{Data: data[50:100]})
		if id, reply := p.client.receiveReply(t); id != 3 || !equalReplies(reply, &sftpwire.DataReply{Data: data[50:100]}) {
			t.Fatalf("reply = %d %s, want 3 with the 50 bytes below the cutoff", id, describe(reply))
		}

		// At or beyond it, the read gets the result without the backend.
		for i, offset := range []uint64{100, 150} {
			id := uint32(4 + i)
			p.client.send(t, id, &sftpwire.Read{Handle: "h", Offset: offset, Length: 50})
			p.client.assertStatus(t, id, sftpwire.StatusFailure, "Failure")
		}
		fb.assertNoRequest(t)

		p.client.send(t, 6, &sftpwire.Close{Handle: "h"})
		fb.reply(t, fb.next(t).id, status(sftpwire.StatusOK))
		p.client.assertReplies(t, 6)
		if got := snaps.taken(); len(got) != 0 {
			t.Errorf("snapshots of %q, want none for a download", got)
		}
		logs.assertLogged(t, `level=INFO msg="injected fault" request=SSH_FXP_READ path=/f fault=partial_download cutoff=100 offset=50 length=100`)
		logs.assertLogged(t, `level=INFO msg="injected fault" request=SSH_FXP_READ path=/f fault=fail when=before status=SSH_FX_FAILURE cutoff=100 offset=100`)
		if n := strings.Count(logs.String(), "injected fault"); n != 2 {
			t.Errorf("logged %d faults at info level, want the shortened read and the first result:\n%s", n, logs.String())
		}
	})
}

func TestPartialDownloadDropsAfterTheReadsBelowItsCutoff(t *testing.T) {
	results := []struct {
		result sftpproxy.Action
		events []string
	}{
		{sftpproxy.Drop{}, []string{"close"}},
		{sftpproxy.Drop{Reset: true}, []string{"reset"}},
		{sftpproxy.Freeze{Limit: time.Minute}, []string{"freeze", "close"}},
	}
	for _, order := range replyOrders {
		for _, tt := range results {
			t.Run(fmt.Sprintf("%v/%T/%v", order, tt.result, tt.events), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					p, fb := startProxyOnFake(t, sftpproxy.Options{
						Faults:     inSequence(sftpproxy.PartialDownload{Cutoff: 100, Result: tt.result}),
						ReplyOrder: order,
					})
					openForDownload(t, p, fb)
					data := bytes.Repeat([]byte{'x'}, 200)

					// A client that pipelines its reads gets every byte below
					// the cutoff before the connection goes.
					p.client.sendTogether(t,
						&sftpwire.Read{Handle: "h", Offset: 0, Length: 60},
						&sftpwire.Read{Handle: "h", Offset: 60, Length: 60},
						&sftpwire.Read{Handle: "h", Offset: 120, Length: 60},
					)
					for _, want := range []sftpwire.Read{{Offset: 0, Length: 60}, {Offset: 60, Length: 40}} {
						req := fb.next(t)
						if r := req.packet.(*sftpwire.Read); r.Offset != want.Offset || r.Length != want.Length {
							t.Fatalf("backend received a read of %d at %d, want %d at %d", r.Length, r.Offset, want.Length, want.Offset)
						}
						fb.reply(t, req.id, &sftpwire.DataReply{Data: data[want.Offset : want.Offset+uint64(want.Length)]})
					}
					var got []byte
					for range 2 {
						_, reply := p.client.receiveReply(t)
						got = append(got, reply.(*sftpwire.DataReply).Data...)
					}
					if !bytes.Equal(got, data[:100]) {
						t.Errorf("client got %d bytes, want the 100 below the cutoff", len(got))
					}
					if _, ok := tt.result.(sftpproxy.Freeze); ok {
						time.Sleep(time.Minute)
					}
					p.client.assertClosed(t)
					fb.assertNoRequest(t)
					if got := p.conn.events(); !slices.Equal(got, tt.events) {
						t.Errorf("connection events = %q, want %q", got, tt.events)
					}
				})
			})
		}
	}
}

func TestPartialDownloadIsReservedBeforeItsFirstCut(t *testing.T) {
	for _, reserved := range []bool{true, false} {
		t.Run(fmt.Sprintf("reserved %v", reserved), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var calls int
				p, fb := startProxyOnFake(t, sftpproxy.Options{Faults: inSequence(sftpproxy.PartialDownload{
					Cutoff:  100,
					Result:  sftpproxy.Fail{Status: sftpwire.StatusFailure},
					Reserve: func() bool { calls++; return reserved },
				})})
				openForDownload(t, p, fb)

				for i, r := range []read{{0, 50}, {90, 20}, {110, 20}} {
					id := uint32(i + 2)
					p.client.send(t, id, &sftpwire.Read{Handle: "h", Offset: r.offset, Length: r.length})
					synctest.Wait()
					if want := min(i, 1); calls != want {
						t.Fatalf("Reserve called %d times after %d reads, want %d", calls, i+1, want)
					}
					if reserved && i > 0 {
						// The other tests check what the cutoff does.
						break
					}
					req := fb.next(t)
					if got := req.packet.(*sftpwire.Read); got.Offset != r.offset || got.Length != r.length {
						t.Fatalf("backend received a read of %d at %d, want the read the declined cutoff leaves alone", got.Length, got.Offset)
					}
					fb.reply(t, req.id, &sftpwire.DataReply{Data: make([]byte, r.length)})
					p.client.assertReplies(t, id)
				}
				if calls != 1 {
					t.Errorf("Reserve called %d times, want once, at the first read that reaches the cutoff", calls)
				}
			})
		})
	}
}
