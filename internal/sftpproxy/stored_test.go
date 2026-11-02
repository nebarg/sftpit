package sftpproxy_test

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

func TestCorruptUploadStoresOneFileHoweverItIsWritten(t *testing.T) {
	file := make([]byte, 200_000)
	rand.NewChaCha8([32]byte{}).Read(file)
	flipped := slices.Clone(file)
	for i := range 30 {
		flipped[99_990+i] ^= 1
	}
	tests := []struct {
		name       string
		corruption sftpproxy.CorruptUpload
		// stored is the file the backend must end up with.
		stored []byte
	}{
		{
			name:       "truncate",
			corruption: sftpproxy.CorruptUpload{Corruption: sftpproxy.Truncate, Offset: 100_000},
			stored:     file[:100_000],
		},
		{
			name:       "truncate to nothing",
			corruption: sftpproxy.CorruptUpload{Corruption: sftpproxy.Truncate},
		},
		{
			name:       "truncate beyond the end",
			corruption: sftpproxy.CorruptUpload{Corruption: sftpproxy.Truncate, Offset: 210_000},
			stored:     file,
		},
		{
			name:       "omit a range",
			corruption: sftpproxy.CorruptUpload{Corruption: sftpproxy.OmitRange, Offset: 70_000, Length: 50_000},
			stored:     slices.Concat(file[:70_000], file[120_000:]),
		},
		{
			name:       "omit the end",
			corruption: sftpproxy.CorruptUpload{Corruption: sftpproxy.OmitRange, Offset: 150_000, Length: 50_000},
			stored:     file[:150_000],
		},
		{
			name:       "omit beyond the end",
			corruption: sftpproxy.CorruptUpload{Corruption: sftpproxy.OmitRange, Offset: 150_000, Length: 1 << 40},
			stored:     file[:150_000],
		},
		{
			name:       "flip bytes",
			corruption: sftpproxy.CorruptUpload{Corruption: sftpproxy.FlipBytes, Offset: 99_990, Length: 30},
			stored:     flipped,
		},
	}

	for _, order := range replyOrders {
		for _, tt := range tests {
			for _, size := range []int{readSize, 1000, 7777} {
				for _, shuffled := range []bool{false, true} {
					name := fmt.Sprintf("%v/%s/writes of %d", order, tt.name, size)
					if shuffled {
						name += " shuffled"
					}
					t.Run(name, func(t *testing.T) {
						synctest.Test(t, func(t *testing.T) {
							p := startProxy(t, inMemoryBackend(t), sftpproxy.Options{
								Faults: faultsOf(func(r sftpproxy.Request) sftpproxy.Action {
									if open, ok := r.Packet.(*sftpwire.Open); ok && open.Flags&sftpwire.OpenWrite != 0 {
										return tt.corruption
									}
									return nil
								}),
								ReplyOrder: order,
							})
							p.client.init(t, 3)
							h := openFile(t, p.client, "/f", sftpwire.OpenWrite|sftpwire.OpenCreate|sftpwire.OpenTruncate)

							var writes []sftpwire.Packet
							for offset := 0; offset < len(file); offset += size {
								writes = append(writes, &sftpwire.Write{Handle: h, Offset: uint64(offset), Data: file[offset:min(offset+size, len(file))]})
							}
							if shuffled {
								rand.New(rand.NewChaCha8([32]byte{2})).Shuffle(len(writes), func(i, j int) { writes[i], writes[j] = writes[j], writes[i] })
							}
							// Every write is answered with success, in batches
							// pipelined as a client such as phpseclib sends them.
							for batch := range slices.Chunk(writes, 32) {
								p.client.sendTogether(t, batch...)
								for range batch {
									if id, reply := p.client.receiveReply(t); !isOK(reply) {
										t.Fatalf("write %d = %s, want success", id, describe(reply))
									}
								}
							}
							p.client.send(t, 1, &sftpwire.Close{Handle: h})
							assertOK(t, p.client, 1)

							if got := readFile(t, p.client, "/f"); !bytes.Equal(got, tt.stored) {
								t.Errorf("stored %d bytes, want %d of the corrupted file", len(got), len(tt.stored))
							}
						})
					})
				}
			}
		}
	}
}

func isOK(p sftpwire.Packet) bool {
	st, ok := p.(*sftpwire.StatusReply)
	return ok && st.Code == sftpwire.StatusOK
}

// readFile returns what reading name through to EOF returns.
func readFile(t *testing.T, c *rawClient, name string) []byte {
	t.Helper()
	h := openFile(t, c, name, sftpwire.OpenRead)
	var data []byte
	for {
		c.send(t, 2, &sftpwire.Read{Handle: h, Offset: uint64(len(data)), Length: readSize})
		_, reply := c.receiveReply(t)
		d, ok := reply.(*sftpwire.DataReply)
		if !ok {
			break
		}
		data = append(data, d.Data...)
	}
	c.send(t, 3, &sftpwire.Close{Handle: h})
	assertOK(t, c, 3)
	return data
}

func TestCorruptUploadForwardsOnlyWhatItStores(t *testing.T) {
	truncate := sftpproxy.CorruptUpload{Corruption: sftpproxy.Truncate, Offset: 100}
	omit := sftpproxy.CorruptUpload{Corruption: sftpproxy.OmitRange, Offset: 100, Length: 50}
	tests := []struct {
		name       string
		corruption sftpproxy.CorruptUpload
		// write is the offset and length of the client's write.
		write read
		// keep are the ranges of the write's bytes that reach the backend,
		// in order, at offset; none means the write never does.
		offset uint64
		keep   [][2]int
	}{
		{"truncate below", truncate, read{0, 100}, 0, [][2]int{{0, 100}}},
		{"truncate across", truncate, read{90, 20}, 90, [][2]int{{0, 10}}},
		{"truncate beyond", truncate, read{100, 20}, 0, nil},
		{"omit below", omit, read{80, 20}, 80, [][2]int{{0, 20}}},
		{"omit within", omit, read{110, 20}, 0, nil},
		{"omit across the start", omit, read{90, 20}, 90, [][2]int{{0, 10}}},
		{"omit across the end", omit, read{140, 20}, 100, [][2]int{{10, 20}}},
		{"omit across both", omit, read{90, 70}, 90, [][2]int{{0, 10}, {60, 70}}},
		{"omit after", omit, read{150, 20}, 100, [][2]int{{0, 20}}},
		{"flip outside", sftpproxy.CorruptUpload{Corruption: sftpproxy.FlipBytes, Offset: 100, Length: 5}, read{105, 20}, 105, [][2]int{{0, 20}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p, fb := startProxyOnFake(t, sftpproxy.Options{Faults: inSequence(tt.corruption)})
				openForUpload(t, p, fb, "h")

				w := write("h", tt.write.offset, int(tt.write.length))
				var kept []byte
				for _, k := range tt.keep {
					kept = append(kept, w.Data[k[0]:k[1]]...)
				}
				p.client.send(t, 2, w)
				if tt.keep == nil {
					fb.assertNoRequest(t)
				} else {
					req := fb.next(t)
					if got, ok := req.packet.(*sftpwire.Write); !ok || got.Offset != tt.offset || !bytes.Equal(got.Data, kept) {
						t.Fatalf("backend received %#v, want a write of %v at %d", req.packet, kept, tt.offset)
					}
					fb.reply(t, req.id, status(sftpwire.StatusOK))
				}
				p.client.assertStatus(t, 2, sftpwire.StatusOK, "Success")
			})
		})
	}
}

func TestCorruptUploadIsReservedBeforeItsFirstChange(t *testing.T) {
	const at, length = 100, 50
	for _, corruption := range []sftpproxy.Corruption{sftpproxy.Truncate, sftpproxy.OmitRange, sftpproxy.FlipBytes} {
		for _, reserved := range []bool{true, false} {
			t.Run(fmt.Sprintf("%v/reserved %v", corruption, reserved), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					var calls int
					p, fb := startProxyOnFake(t, sftpproxy.Options{Faults: inSequence(sftpproxy.CorruptUpload{
						Corruption: corruption,
						Offset:     at,
						Length:     length,
						Reserve:    func() bool { calls++; return reserved },
					})})
					openForUpload(t, p, fb, "h")

					for i, r := range []read{{0, 50}, {90, 20}, {110, 20}} {
						id := uint32(i + 2)
						p.client.send(t, id, write("h", r.offset, int(r.length)))
						synctest.Wait()
						if want := min(i, 1); calls != want {
							t.Fatalf("Reserve called %d times after %d writes, want %d", calls, i+1, want)
						}
						if reserved {
							// Other tests check what the corruption stores.
							continue
						}
						req := fb.next(t)
						if got, ok := req.packet.(*sftpwire.Write); !ok || got.Offset != r.offset || len(got.Data) != int(r.length) {
							t.Fatalf("backend received %#v, want the write the declined corruption leaves alone", req.packet)
						}
						fb.reply(t, req.id, status(sftpwire.StatusOK))
						p.client.assertStatus(t, id, sftpwire.StatusOK, "Success")
					}
					if calls != 1 {
						t.Errorf("Reserve called %d times, want once, at the first write the corruption changes", calls)
					}
				})
			})
		}
	}
}

func TestCorruptUploadSnapshotsTheFileItChanged(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs syncBuffer
		var snaps snapshots
		p, fb := startProxyOnFake(t, sftpproxy.Options{
			Faults:   inSequence(sftpproxy.CorruptUpload{Corruption: sftpproxy.Truncate, Offset: 10}),
			Snapshot: snaps.take,
			Logger:   logs.logger(),
		})
		openForUpload(t, p, fb, "h")

		p.client.send(t, 2, write("h", 0, 20))
		req := fb.next(t)
		fb.reply(t, req.id, status(sftpwire.StatusOK))
		p.client.assertStatus(t, 2, sftpwire.StatusOK, "Success")
		p.client.send(t, 3, write("h", 20, 20))
		p.client.assertStatus(t, 3, sftpwire.StatusOK, "Success")
		p.client.send(t, 4, &sftpwire.Close{Handle: "h"})
		fb.reply(t, fb.next(t).id, status(sftpwire.StatusOK))
		p.client.assertStatus(t, 4, sftpwire.StatusOK, "Success")

		if got := snaps.taken(); !slices.Equal(got, []string{"/f"}) {
			t.Errorf("snapshots of %q, want /f once", got)
		}
		// Only the first write the corruption changes is the fault; the
		// rest are its effects, logged at debug level.
		logs.assertLogged(t, `level=INFO msg="injected fault" request=SSH_FXP_WRITE path=/f fault=corrupt_upload corruption=truncate at=10 offset=0`)
		if n := strings.Count(logs.String(), "injected fault"); n != 1 {
			t.Errorf("logged %d faults at info level, want 1:\n%s", n, logs.String())
		}
	})
}
