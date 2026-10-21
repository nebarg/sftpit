package sftpproxy_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

const cutoff = 100

var replyOrders = []sftpproxy.ReplyOrder{sftpproxy.RequestOrder, sftpproxy.CompletionOrder}

func TestPartialUploadDecidesEachWriteByItsOffset(t *testing.T) {
	// The writes arrive out of order, overlap and skip offsets, and the
	// cutoff is reached before the writes below it have all arrived.
	writes := []struct {
		offset uint64
		length int
		// forwarded is how many bytes reach the backend, or -1 for none.
		forwarded int
		status    sftpwire.StatusCode
	}{
		{offset: 150, length: 10, forwarded: -1, status: sftpwire.StatusFailure},
		{offset: 0, length: 50, forwarded: 50, status: sftpwire.StatusOK},
		{offset: 90, length: 20, forwarded: 10, status: sftpwire.StatusFailure},
		{offset: 50, length: 50, forwarded: 50, status: sftpwire.StatusOK},
		{offset: 40, length: 20, forwarded: 20, status: sftpwire.StatusOK},
		{offset: 99, length: 2, forwarded: 1, status: sftpwire.StatusFailure},
		{offset: 10, length: 0, forwarded: 0, status: sftpwire.StatusOK},
		{offset: cutoff, length: 0, forwarded: -1, status: sftpwire.StatusFailure},
		{offset: 1 << 40, length: 5, forwarded: -1, status: sftpwire.StatusFailure},
	}

	for _, order := range replyOrders {
		t.Run(order.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var logs syncBuffer
				var seen []sftpwire.Packet
				fail := sftpproxy.PartialUpload{Cutoff: cutoff, Result: sftpproxy.Fail{Status: sftpwire.StatusFailure}}
				p, fb := startProxyOnFake(t, sftpproxy.Options{
					Faults: func(r sftpproxy.Request) sftpproxy.Action {
						seen = append(seen, r.Packet)
						if _, ok := r.Packet.(*sftpwire.Open); ok {
							return fail
						}
						return nil
					},
					ReplyOrder: order,
					Logger:     slog.New(slog.NewTextHandler(&logs, nil)),
				})
				openForUpload(t, p, fb, "h")

				for i, w := range writes {
					id := uint32(i + 2)
					sent := write("h", w.offset, w.length)
					p.client.send(t, id, sent)
					if w.forwarded >= 0 {
						req := fb.next(t)
						got, ok := req.packet.(*sftpwire.Write)
						if !ok || got.Offset != w.offset || !bytes.Equal(got.Data, sent.Data[:w.forwarded]) {
							t.Fatalf("backend received %#v for the write at %d, want its first %d bytes", req.packet, w.offset, w.forwarded)
						}
						fb.reply(t, req.id, status(sftpwire.StatusOK))
					}
					p.client.assertStatus(t, id, w.status, w.status.Message())
				}
				fb.assertNoRequest(t)

				for _, packet := range seen {
					if w, ok := packet.(*sftpwire.Write); ok && w.Offset+uint64(len(w.Data)) > cutoff {
						t.Errorf("Faults saw the write at %d, which the cutoff decides", w.Offset)
					}
				}
				want := `level=INFO msg="injected fault" request=SSH_FXP_WRITE path=/f fault=fail when=before status=SSH_FX_FAILURE cutoff=100 offset=150`
				if got := strings.Count(logs.String(), "injected fault"); got != 1 || !strings.Contains(logs.String(), want) {
					t.Errorf("log has %d faults, want only %q:\n%s", got, want, logs.String())
				}
			})
		})
	}
}

func TestPartialUploadAppliesOnlyToItsHandle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fail := sftpproxy.PartialUpload{Cutoff: cutoff, Result: sftpproxy.Fail{Status: sftpwire.StatusFailure}}
		p, fb := startProxyOnFake(t, sftpproxy.Options{Faults: inSequence(fail)})
		openForUpload(t, p, fb, "first")
		openForUpload(t, p, fb, "second")

		p.client.send(t, 2, write("first", cutoff, 10))
		p.client.assertStatus(t, 2, sftpwire.StatusFailure, "Failure")
		p.client.send(t, 3, write("second", cutoff, 10))
		fb.reply(t, fb.next(t).id, status(sftpwire.StatusOK))
		p.client.assertStatus(t, 3, sftpwire.StatusOK, "Success")
	})
}

func TestPartialUploadIsReservedWhereItFirstCuts(t *testing.T) {
	for _, reserved := range []bool{true, false} {
		t.Run(fmt.Sprintf("reserved %v", reserved), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var calls int
				p, fb := startProxyOnFake(t, sftpproxy.Options{Faults: inSequence(sftpproxy.PartialUpload{
					Cutoff:  cutoff,
					Result:  sftpproxy.Fail{Status: sftpwire.StatusFailure},
					Reserve: func() bool { calls++; return reserved },
				})})
				openForUpload(t, p, fb, "h")

				p.client.send(t, 2, write("h", 0, cutoff))
				fb.reply(t, fb.next(t).id, status(sftpwire.StatusOK))
				p.client.assertStatus(t, 2, sftpwire.StatusOK, "Success")
				if calls != 0 {
					t.Fatalf("Reserve called %d times before a write reached the cutoff", calls)
				}
				for id := uint32(3); id <= 4; id++ {
					w := write("h", cutoff, 10)
					p.client.send(t, id, w)
					if reserved {
						p.client.assertStatus(t, id, sftpwire.StatusFailure, "Failure")
						continue
					}
					if got := fb.next(t); !equalReplies(got.packet, w) {
						t.Fatalf("backend received %#v, want the whole write, which the declined cutoff leaves alone", got.packet)
					} else {
						fb.reply(t, got.id, status(sftpwire.StatusOK))
					}
					p.client.assertStatus(t, id, sftpwire.StatusOK, "Success")
				}
				if calls != 1 {
					t.Errorf("Reserve called %d times, want once, at the first write to reach the cutoff", calls)
				}
			})
		})
	}
}

func TestPartialUploadDropsAtTheCutoff(t *testing.T) {
	results := []struct {
		name   string
		result func(release <-chan struct{}) sftpproxy.Action
		events []string
	}{
		{
			name:   "FIN",
			result: func(<-chan struct{}) sftpproxy.Action { return sftpproxy.Drop{} },
			events: []string{"close"},
		},
		{
			name:   "RST",
			result: func(<-chan struct{}) sftpproxy.Action { return sftpproxy.Drop{Reset: true} },
			events: []string{"reset"},
		},
		{
			name: "freeze",
			result: func(release <-chan struct{}) sftpproxy.Action {
				return sftpproxy.Freeze{Release: release, Limit: time.Hour}
			},
			events: []string{"freeze", "close"},
		},
	}
	reaches := []struct {
		name   string
		writes []sftpwire.Packet
		// replies are the requests the client gets replies to before the
		// drop. The backend receives the first two writes, up to the cutoff.
		replies []uint32
	}{
		{
			name:    "crossing",
			writes:  []sftpwire.Packet{write("h", 0, 50), write("h", 50, 60), write("h", 110, 50)},
			replies: []uint32{1},
		},
		{
			name:    "at",
			writes:  []sftpwire.Packet{write("h", 0, 50), write("h", 50, 50), write("h", 100, 50), write("h", 150, 50)},
			replies: []uint32{1, 2},
		},
	}

	for _, order := range replyOrders {
		for _, r := range results {
			for _, reach := range reaches {
				t.Run(order.String()+"/"+r.name+"/"+reach.name, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						release := make(chan struct{})
						p, fb := startProxyOnFake(t, sftpproxy.Options{
							Faults:     inSequence(sftpproxy.PartialUpload{Cutoff: cutoff, Result: r.result(release)}),
							ReplyOrder: order,
						})
						openForUpload(t, p, fb, "h")
						p.client.sendTogether(t, reach.writes...)

						first, second := fb.next(t), fb.next(t)
						stored := slices.Concat(first.packet.(*sftpwire.Write).Data, second.packet.(*sftpwire.Write).Data)
						if want := write("h", 0, cutoff).Data; !bytes.Equal(stored, want) {
							t.Errorf("backend received %v, want %v", stored, want)
						}
						fb.assertNoRequest(t)
						if got := p.conn.events(); len(got) != 0 {
							t.Fatalf("connection %v while the backend still had writes", got)
						}

						fb.reply(t, first.id, status(sftpwire.StatusOK))
						fb.reply(t, second.id, status(sftpwire.StatusOK))
						p.client.assertReplies(t, reach.replies...)
						close(release)
						p.client.assertClosed(t)
						if err := p.result.wait(t); err != nil {
							t.Errorf("Serve after a drop = %v, want nil", err)
						}
						if got := p.conn.events(); !slices.Equal(got, r.events) {
							t.Errorf("connection events = %v, want %v", got, r.events)
						}
						fb.assertNoRequest(t)
					})
				})
			}
		}
	}
}

// openForUpload opens /f for writing as request 1, with the backend
// answering handle.
func openForUpload(t *testing.T, p *proxy, fb *fakeBackend, handle string) {
	t.Helper()
	p.client.send(t, 1, &sftpwire.Open{Path: "/f", Flags: sftpwire.OpenWrite | sftpwire.OpenCreate | sftpwire.OpenTruncate})
	fb.reply(t, fb.next(t).id, &sftpwire.HandleReply{Handle: handle})
	p.client.assertReplies(t, 1)
}

// write returns a WRITE of length bytes at offset whose every byte is the
// low byte of its own offset, so any part of it can be told apart.
func write(handle string, offset uint64, length int) *sftpwire.Write {
	data := make([]byte, length)
	for i := range data {
		data[i] = byte(offset + uint64(i))
	}
	return &sftpwire.Write{Handle: handle, Offset: offset, Data: data}
}

func status(code sftpwire.StatusCode) *sftpwire.StatusReply {
	return &sftpwire.StatusReply{Code: code, Message: code.Message()}
}
