package sftpproxy_test

import (
	"bytes"
	"fmt"
	"math"
	"math/rand/v2"
	"slices"
	"testing"
	"testing/synctest"

	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

// readSize is the most a test reads at once, pkg/sftp's limit on a read.
const readSize = 32 * 1024

func TestCorruptDownloadServesOneFileHoweverItIsRead(t *testing.T) {
	file := make([]byte, 200_000)
	rand.NewChaCha8([32]byte{}).Read(file)
	flipped := slices.Clone(file)
	for i := range 30 {
		flipped[99_990+i] ^= 1
	}
	tests := []struct {
		name       string
		corruption sftpproxy.CorruptDownload
		// served is the file the client must see.
		served []byte
	}{
		{
			name:       "truncate",
			corruption: sftpproxy.CorruptDownload{Corruption: sftpproxy.Truncate, Offset: 100_000},
			served:     file[:100_000],
		},
		{
			name:       "truncate to nothing",
			corruption: sftpproxy.CorruptDownload{Corruption: sftpproxy.Truncate},
		},
		{
			name:       "truncate beyond the end",
			corruption: sftpproxy.CorruptDownload{Corruption: sftpproxy.Truncate, Offset: 210_000},
			served:     file,
		},
		{
			name:       "omit a range",
			corruption: sftpproxy.CorruptDownload{Corruption: sftpproxy.OmitRange, Offset: 70_000, Length: 50_000},
			served:     slices.Concat(file[:70_000], file[120_000:]),
		},
		{
			name:       "omit the end",
			corruption: sftpproxy.CorruptDownload{Corruption: sftpproxy.OmitRange, Offset: 150_000, Length: 50_000},
			served:     file[:150_000],
		},
		{
			name:       "omit beyond the end",
			corruption: sftpproxy.CorruptDownload{Corruption: sftpproxy.OmitRange, Offset: 150_000, Length: 1 << 40},
			served:     file[:150_000],
		},
		{
			name:       "flip bytes",
			corruption: sftpproxy.CorruptDownload{Corruption: sftpproxy.FlipBytes, Offset: 99_990, Length: 30},
			served:     flipped,
		},
	}
	reads := readsOf(len(file)+20_000, 70_000, 99_990, 100_000, 100_020, 120_000, 150_000, 200_000, 210_000)

	for _, order := range replyOrders {
		for _, tt := range tests {
			// In a bubble, the in-memory backend's simulated write delay
			// passes at once.
			t.Run(order.String()+"/"+tt.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					p := startProxy(t, inMemoryBackend(t), sftpproxy.Options{
						Faults: func(r sftpproxy.Request) sftpproxy.Action {
							if open, ok := r.Packet.(*sftpwire.Open); ok && open.Flags&sftpwire.OpenWrite == 0 {
								return tt.corruption
							}
							return nil
						},
						ReplyOrder: order,
					})
					p.client.init(t, 3)
					storeFile(t, p.client, "/f", file)
					h := openFile(t, p.client, "/f", sftpwire.OpenRead)

					// The reads are pipelined in batches, so each batch is
					// answered in whatever order the session delivers.
					for batch := range slices.Chunk(reads, 32) {
						var requests []sftpwire.Packet
						for _, r := range batch {
							requests = append(requests, &sftpwire.Read{Handle: h, Offset: r.offset, Length: r.length})
						}
						p.client.sendTogether(t, requests...)
						for range batch {
							id, reply := p.client.receiveReply(t)
							assertServed(t, batch[id-1], reply, tt.served)
						}
					}
					p.client.send(t, 1, &sftpwire.Close{Handle: h})
					assertOK(t, p.client, 1)
				})
			})
		}
	}
}

// read is the offset and length of a READ.
type read struct {
	offset uint64
	length uint32
}

// readsOf returns reads of a file of up to size bytes: through all of it in
// several read sizes, across and next to each boundary, and at random.
func readsOf(size int, boundaries ...uint64) []read {
	var reads []read
	for _, length := range []uint32{readSize, 1000, 7777} {
		for offset := uint64(0); offset < uint64(size); offset += uint64(length) {
			reads = append(reads, read{offset, length})
		}
	}
	for _, b := range boundaries {
		for _, offset := range []uint64{b - 11, b - 1, b, b + 1} {
			for _, length := range []uint32{1, 2, 11, readSize} {
				reads = append(reads, read{offset, length})
			}
		}
	}
	r := rand.New(rand.NewChaCha8([32]byte{1}))
	for range 300 {
		reads = append(reads, read{r.Uint64N(uint64(size)), 1 + r.Uint32N(readSize)})
	}
	return reads
}

// assertServed checks that reply returns what r reads of served.
func assertServed(t *testing.T, r read, reply sftpwire.Packet, served []byte) {
	t.Helper()
	if r.offset >= uint64(len(served)) {
		if st, ok := reply.(*sftpwire.StatusReply); !ok || st.Code != sftpwire.StatusEOF {
			t.Fatalf("read of %d at %d = %#v, want EOF", r.length, r.offset, reply)
		}
		return
	}
	want := served[r.offset:min(r.offset+uint64(r.length), uint64(len(served)))]
	if data, ok := reply.(*sftpwire.DataReply); !ok || !bytes.Equal(data.Data, want) {
		t.Fatalf("read of %d at %d = %s, want %d bytes from %d of the served file", r.length, r.offset, describe(reply), len(want), r.offset)
	}
}

func describe(reply sftpwire.Packet) string {
	if data, ok := reply.(*sftpwire.DataReply); ok {
		return fmt.Sprintf("%d other bytes", len(data.Data))
	}
	return fmt.Sprintf("%#v", reply)
}

func TestCorruptDownloadForwardsOnlyWhatItNeeds(t *testing.T) {
	type forwardedRead struct {
		read
		// forwarded are the reads that reach the backend for it.
		forwarded []read
		// changed is set for a read that the corruption changes, which
		// Faults must not see.
		changed bool
	}
	const at, length = 100, 50
	tests := []struct {
		name       string
		corruption sftpproxy.Corruption
		reads      []forwardedRead
		// log is the fault logged for the first read the corruption
		// changes.
		log string
	}{
		{
			name:       "truncate",
			corruption: sftpproxy.Truncate,
			reads: []forwardedRead{
				{read: read{0, 50}, forwarded: []read{{0, 50}}},
				{read: read{90, 20}, forwarded: []read{{90, 10}}, changed: true},
				{read: read{100, 10}, changed: true},
				{read: read{150, 10}, changed: true},
				{read: read{80, 20}, forwarded: []read{{80, 20}}},
			},
			log: `level=INFO msg="injected fault" request=SSH_FXP_READ path=/f fault=corrupt_download corruption=truncate at=100 offset=90`,
		},
		{
			name:       "omit a range",
			corruption: sftpproxy.OmitRange,
			reads: []forwardedRead{
				{read: read{0, 50}, forwarded: []read{{0, 50}}},
				{read: read{90, 20}, forwarded: []read{{90, 10}, {150, 10}}, changed: true},
				{read: read{100, 10}, forwarded: []read{{150, 10}}, changed: true},
				{read: read{math.MaxUint64 - 10, 5}, changed: true},
				{read: read{80, 20}, forwarded: []read{{80, 20}}},
			},
			log: `level=INFO msg="injected fault" request=SSH_FXP_READ path=/f fault=corrupt_download corruption=omit_range at=100 length=50 offset=90`,
		},
		{
			name:       "flip bytes",
			corruption: sftpproxy.FlipBytes,
			reads: []forwardedRead{
				{read: read{0, 50}, forwarded: []read{{0, 50}}},
				{read: read{90, 20}, forwarded: []read{{90, 20}}, changed: true},
				{read: read{149, 1}, forwarded: []read{{149, 1}}, changed: true},
				{read: read{150, 10}, forwarded: []read{{150, 10}}},
				{read: read{80, 20}, forwarded: []read{{80, 20}}},
			},
			log: `level=INFO msg="injected fault" request=SSH_FXP_READ path=/f fault=corrupt_download corruption=flip_bytes at=100 length=50 offset=90`,
		},
	}

	for _, order := range replyOrders {
		for _, tt := range tests {
			t.Run(order.String()+"/"+tt.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					var logs syncBuffer
					var seen []read
					corruption := sftpproxy.CorruptDownload{Corruption: tt.corruption, Offset: at, Length: length}
					p, fb := startProxyOnFake(t, sftpproxy.Options{
						Faults: func(r sftpproxy.Request) sftpproxy.Action {
							switch p := r.Packet.(type) {
							case *sftpwire.Open:
								return corruption
							case *sftpwire.Read:
								seen = append(seen, read{p.Offset, p.Length})
							}
							return nil
						},
						ReplyOrder: order,
						Logger:     logs.logger(),
					})
					openForDownload(t, p, fb, "h")

					var unchanged []read
					for i, r := range tt.reads {
						id := uint32(i + 2)
						p.client.send(t, id, &sftpwire.Read{Handle: "h", Offset: r.offset, Length: r.length})
						var reqs []backendRequest
						for range r.forwarded {
							reqs = append(reqs, fb.next(t))
						}
						var got []read
						for _, req := range reqs {
							rd, ok := req.packet.(*sftpwire.Read)
							if !ok {
								t.Fatalf("backend received %#v, want a READ", req.packet)
							}
							got = append(got, read{rd.Offset, rd.Length})
							fb.reply(t, req.id, &sftpwire.DataReply{Data: make([]byte, rd.Length)})
						}
						if !slices.Equal(got, r.forwarded) {
							t.Errorf("the read of %d at %d reached the backend as %v, want %v", r.length, r.offset, got, r.forwarded)
						}
						if len(r.forwarded) == 0 {
							p.client.assertStatus(t, id, sftpwire.StatusEOF, "End of file")
						} else if gotID := p.client.nextReplyID(t); gotID != id {
							t.Errorf("received a reply to request %d, want one to %d", gotID, id)
						}
						if !r.changed {
							unchanged = append(unchanged, r.read)
						}
					}
					fb.assertNoRequest(t)

					if !slices.Equal(seen, unchanged) {
						t.Errorf("Faults saw reads %v, want only those the corruption leaves alone, %v", seen, unchanged)
					}
					logs.assertOnlyFault(t, tt.log)
				})
			})
		}
	}
}

func TestCorruptDownloadIsReservedBeforeItsFirstChange(t *testing.T) {
	data := make([]byte, 200)
	for i := range data {
		data[i] = byte(i)
	}
	const at, length = 100, 50
	for _, corruption := range []sftpproxy.Corruption{sftpproxy.Truncate, sftpproxy.OmitRange, sftpproxy.FlipBytes} {
		for _, reserved := range []bool{true, false} {
			t.Run(fmt.Sprintf("%v/reserved %v", corruption, reserved), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					var calls int
					p, fb := startProxyOnFake(t, sftpproxy.Options{Faults: inSequence(sftpproxy.CorruptDownload{
						Corruption: corruption,
						Offset:     at,
						Length:     length,
						Reserve:    func() bool { calls++; return reserved },
					})})
					openForDownload(t, p, fb, "h")

					for i, r := range []read{{0, 50}, {90, 20}, {110, 20}} {
						id := uint32(i + 2)
						p.client.send(t, id, &sftpwire.Read{Handle: "h", Offset: r.offset, Length: r.length})
						synctest.Wait()
						if want := min(i, 1); calls != want {
							t.Fatalf("Reserve called %d times after %d reads, want %d", calls, i+1, want)
						}
						if reserved {
							// Other tests check what the corruption serves.
							continue
						}
						req := fb.next(t)
						if got, ok := req.packet.(*sftpwire.Read); !ok || got.Offset != r.offset || got.Length != r.length {
							t.Fatalf("backend received %#v, want the read the declined corruption leaves alone", req.packet)
						}
						fb.reply(t, req.id, &sftpwire.DataReply{Data: data[r.offset : r.offset+uint64(r.length)]})
						_, reply := p.client.receiveReply(t)
						if want := (&sftpwire.DataReply{Data: data[r.offset : r.offset+uint64(r.length)]}); !equalReplies(reply, want) {
							t.Fatalf("read at %d = %s, want the file as it is", r.offset, describe(reply))
						}
					}
					if calls != 1 {
						t.Errorf("Reserve called %d times, want once, at the first read the corruption changes", calls)
					}
				})
			})
		}
	}
}

func TestSplitReadJoinsWhatTheBackendReturns(t *testing.T) {
	// A read of 20 at 90 crosses an omitted range of 50 at 100, so it reaches
	// the backend as a read of 10 at 90 and one of 10 at 150.
	before, after := bytes.Repeat([]byte("b"), 10), bytes.Repeat([]byte("a"), 10)
	failure := status(sftpwire.StatusFailure)
	tests := []struct {
		name string
		// replies are the backend's replies to the read before the range
		// and the read after it.
		replies [2]sftpwire.Packet
		// afterFirst answers the read after the range first.
		afterFirst bool
		want       sftpwire.Packet
	}{
		{
			name:    "bytes on both sides",
			replies: [2]sftpwire.Packet{&sftpwire.DataReply{Data: before}, &sftpwire.DataReply{Data: after}},
			want:    &sftpwire.DataReply{Data: slices.Concat(before, after)},
		},
		{
			name:       "answered in the other order",
			replies:    [2]sftpwire.Packet{&sftpwire.DataReply{Data: before}, &sftpwire.DataReply{Data: after}},
			afterFirst: true,
			want:       &sftpwire.DataReply{Data: slices.Concat(before, after)},
		},
		{
			name:    "the file ends in the range",
			replies: [2]sftpwire.Packet{&sftpwire.DataReply{Data: before}, status(sftpwire.StatusEOF)},
			want:    &sftpwire.DataReply{Data: before},
		},
		{
			name:    "a short read before the range",
			replies: [2]sftpwire.Packet{&sftpwire.DataReply{Data: before[:4]}, &sftpwire.DataReply{Data: after}},
			want:    &sftpwire.DataReply{Data: before[:4]},
		},
		{
			name:    "the file ends before the range",
			replies: [2]sftpwire.Packet{status(sftpwire.StatusEOF), status(sftpwire.StatusEOF)},
			want:    status(sftpwire.StatusEOF),
		},
		{
			name:    "the read before the range fails",
			replies: [2]sftpwire.Packet{failure, &sftpwire.DataReply{Data: after}},
			want:    failure,
		},
		{
			name:    "the read after the range fails",
			replies: [2]sftpwire.Packet{&sftpwire.DataReply{Data: before}, failure},
			want:    &sftpwire.DataReply{Data: before},
		},
	}

	for _, order := range replyOrders {
		for _, tt := range tests {
			t.Run(order.String()+"/"+tt.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					p, fb := startProxyOnFake(t, sftpproxy.Options{
						Faults:     on[*sftpwire.Open](sftpproxy.CorruptDownload{Corruption: sftpproxy.OmitRange, Offset: 100, Length: 50}),
						ReplyOrder: order,
					})
					openForDownload(t, p, fb, "h")

					p.client.send(t, 2, &sftpwire.Read{Handle: "h", Offset: 90, Length: 20})
					reqs := []backendRequest{fb.next(t), fb.next(t)}
					if tt.afterFirst {
						fb.reply(t, reqs[1].id, tt.replies[1])
						fb.assertNoRequest(t)
						fb.reply(t, reqs[0].id, tt.replies[0])
					} else {
						fb.reply(t, reqs[0].id, tt.replies[0])
						fb.reply(t, reqs[1].id, tt.replies[1])
					}
					if id, got := p.client.receiveReply(t); id != 2 || !equalReplies(got, tt.want) {
						t.Errorf("reply = %d %#v, want 2 %#v", id, got, tt.want)
					}
				})
			})
		}
	}
}

func TestSplitReadIsAnsweredBeforeALaterDrop(t *testing.T) {
	for _, order := range replyOrders {
		t.Run(order.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p, fb := startProxyOnFake(t, sftpproxy.Options{
					Faults: func(r sftpproxy.Request) sftpproxy.Action {
						switch r.Packet.(type) {
						case *sftpwire.Open:
							return sftpproxy.CorruptDownload{Corruption: sftpproxy.OmitRange, Offset: 100, Length: 50}
						case *sftpwire.Stat:
							return sftpproxy.Drop{}
						}
						return nil
					},
					ReplyOrder: order,
				})
				openForDownload(t, p, fb, "h")

				p.client.send(t, 2, &sftpwire.Read{Handle: "h", Offset: 90, Length: 20})
				reqs := []backendRequest{fb.next(t), fb.next(t)}
				p.client.send(t, 3, &sftpwire.Stat{Path: "/g"})
				for _, req := range reqs {
					// The drop must wait for the backend to answer both reads.
					synctest.Wait()
					if events := p.conn.events(); len(events) > 0 {
						t.Fatalf("connection events %v before the backend answered the read, want none", events)
					}
					fb.reply(t, req.id, &sftpwire.DataReply{Data: make([]byte, 10)})
				}
				if id, reply := p.client.receiveReply(t); id != 2 || !equalReplies(reply, &sftpwire.DataReply{Data: make([]byte, 20)}) {
					t.Errorf("reply = %d %#v, want the joined read 2", id, reply)
				}
				p.client.assertClosed(t)
			})
		})
	}
}

// openFile opens name with flags and returns its handle.
func openFile(t *testing.T, c *rawClient, name string, flags uint32) string {
	t.Helper()
	c.send(t, 1, &sftpwire.Open{Path: name, Flags: flags})
	_, reply := c.receiveReply(t)
	h, ok := reply.(*sftpwire.HandleReply)
	if !ok {
		t.Fatalf("OPEN %s = %#v, want a handle", name, reply)
	}
	return h.Handle
}

// storeFile writes data to a new file name.
func storeFile(t *testing.T, c *rawClient, name string, data []byte) {
	t.Helper()
	h := openFile(t, c, name, sftpwire.OpenWrite|sftpwire.OpenCreate|sftpwire.OpenTruncate)
	for offset := 0; offset < len(data); offset += readSize {
		c.send(t, 2, &sftpwire.Write{Handle: h, Offset: uint64(offset), Data: data[offset:min(offset+readSize, len(data))]})
		assertOK(t, c, 2)
	}
	c.send(t, 3, &sftpwire.Close{Handle: h})
	assertOK(t, c, 3)
}

// assertOK checks that the next reply says the request with id succeeded,
// whatever message it gives.
func assertOK(t *testing.T, c *rawClient, id uint32) {
	t.Helper()
	gotID, p := c.receiveReply(t)
	if st, ok := p.(*sftpwire.StatusReply); !ok || gotID != id || st.Code != sftpwire.StatusOK {
		t.Fatalf("reply = %d %#v, want %d OK", gotID, p, id)
	}
}
