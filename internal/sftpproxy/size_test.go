package sftpproxy_test

import (
	"fmt"
	"log/slog"
	"math"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

func TestWrongSizeMisreportsStatReplies(t *testing.T) {
	sizes := []struct {
		name      string
		wrongSize sftpproxy.WrongSize
		actual    uint64
		reported  uint64
	}{
		{name: "size", wrongSize: sftpproxy.WrongSize{Size: 5}, actual: 100, reported: 5},
		{name: "zero", wrongSize: sftpproxy.WrongSize{}, actual: 100, reported: 0},
		{name: "larger", wrongSize: sftpproxy.WrongSize{Delta: 1024}, actual: 100, reported: 1124},
		{name: "smaller", wrongSize: sftpproxy.WrongSize{Delta: -10}, actual: 100, reported: 90},
		{name: "below zero", wrongSize: sftpproxy.WrongSize{Delta: math.MinInt64}, actual: 100, reported: 0},
		{name: "beyond the largest", wrongSize: sftpproxy.WrongSize{Delta: math.MaxInt64}, actual: math.MaxUint64 - 1, reported: math.MaxUint64},
	}
	requests := []sftpwire.Packet{&sftpwire.Stat{Path: "/f"}, &sftpwire.LStat{Path: "/f"}, &sftpwire.FStat{Handle: "h"}}

	for _, tt := range sizes {
		for _, request := range requests {
			t.Run(tt.name+"/"+request.Type().String(), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					var logs syncBuffer
					p, fb := startProxyOnFake(t, sftpproxy.Options{
						Faults: func(r sftpproxy.Request) sftpproxy.Action {
							if _, ok := r.Packet.(*sftpwire.Open); !ok && r.Path == "/f" {
								return tt.wrongSize
							}
							return nil
						},
						Logger: slog.New(slog.NewTextHandler(&logs, nil)),
					})
					openForDownload(t, p, fb, "h")

					attrs := sftpwire.Attrs{Flags: sftpwire.AttrSize | sftpwire.AttrPermissions, Size: tt.actual, Permissions: 0o100644}
					p.client.send(t, 2, request)
					fb.reply(t, fb.next(t).id, &sftpwire.AttrsReply{Attrs: attrs})
					want := attrs
					want.Size = tt.reported
					if id, reply := p.client.receiveReply(t); id != 2 || !equalReplies(reply, &sftpwire.AttrsReply{Attrs: want}) {
						t.Errorf("reply = %d %#v, want 2 with attributes %+v", id, reply, want)
					}
					wantLog := fmt.Sprintf(`level=INFO msg="injected fault" request=%v path=/f fault=wrong_size actual=%d reported=%d`, request.Type(), tt.actual, tt.reported)
					if got := strings.Count(logs.String(), "injected fault"); got != 1 || !strings.Contains(logs.String(), wantLog) {
						t.Errorf("log has %d faults, want only %q:\n%s", got, wantLog, logs.String())
					}
				})
			})
		}
	}
}

func TestWrongSizeLeavesRepliesWithoutASize(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs syncBuffer
		p, fb := startProxyOnFake(t, sftpproxy.Options{
			Faults: on[*sftpwire.Stat](sftpproxy.WrongSize{Size: 5}),
			Logger: slog.New(slog.NewTextHandler(&logs, nil)),
		})
		replies := []sftpwire.Packet{
			&sftpwire.AttrsReply{Attrs: sftpwire.Attrs{Flags: sftpwire.AttrPermissions, Permissions: 0o100644}},
			status(sftpwire.StatusNoSuchFile),
		}
		for i, backendReply := range replies {
			id := uint32(i + 1)
			p.client.send(t, id, &sftpwire.Stat{Path: "/f"})
			fb.reply(t, fb.next(t).id, backendReply)
			if gotID, reply := p.client.receiveReply(t); gotID != id || !equalReplies(reply, backendReply) {
				t.Errorf("reply = %d %#v, want %d %#v unchanged", gotID, reply, id, backendReply)
			}
		}
		if strings.Contains(logs.String(), "injected fault") {
			t.Errorf("logged a fault for replies without a size:\n%s", logs.String())
		}
	})
}

func TestWrongSizeMisreportsTheReaddirEntriesFaultsChooses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex
		var asked []sftpproxy.Request
		p, fb := startProxyOnFake(t, sftpproxy.Options{
			Faults: func(r sftpproxy.Request) sftpproxy.Action {
				mu.Lock()
				defer mu.Unlock()
				asked = append(asked, sftpproxy.Request{Path: r.Path, Entry: r.Entry})
				if r.Entry && r.Path == "/d/b.csv" {
					return sftpproxy.WrongSize{Delta: -1024}
				}
				return nil
			},
		})
		openDir(t, p, fb, "/d")

		p.client.send(t, 2, &sftpwire.ReadDir{Handle: "h"})
		fb.reply(t, fb.next(t).id, &sftpwire.NameReply{Entries: []sftpwire.NameEntry{
			lsEntry("a.csv", 4096, 4096), lsEntry("b.csv", 4096, 4096), lsEntry("c.csv", 4096, 4096),
		}})
		want := &sftpwire.NameReply{Entries: []sftpwire.NameEntry{
			lsEntry("a.csv", 4096, 4096), lsEntry("b.csv", 3072, 3072), lsEntry("c.csv", 4096, 4096),
		}}
		if id, reply := p.client.receiveReply(t); id != 2 || !equalReplies(reply, want) {
			t.Errorf("reply = %d %#v, want 2 %#v", id, reply, want)
		}
		// The entries of an unknown handle have no path to ask about.
		p.client.send(t, 3, &sftpwire.ReadDir{Handle: "unknown"})
		fb.reply(t, fb.next(t).id, &sftpwire.NameReply{Entries: []sftpwire.NameEntry{lsEntry("b.csv", 4096, 4096)}})
		p.client.assertReplies(t, 3)

		mu.Lock()
		defer mu.Unlock()
		wantAsked := []sftpproxy.Request{
			{Path: "/d"},
			{Path: "/d"},
			{Path: "/d/a.csv", Entry: true},
			{Path: "/d/b.csv", Entry: true},
			{Path: "/d/c.csv", Entry: true},
			{Path: ""},
		}
		if !slices.Equal(asked, wantAsked) {
			t.Errorf("Faults was asked about %+v, want %+v", asked, wantAsked)
		}
	})
}

// lsEntry returns a READDIR entry for name whose attributes give size and
// whose longname, in pkg/sftp's ls -l style, shows shown.
func lsEntry(name string, size, shown uint64) sftpwire.NameEntry {
	return sftpwire.NameEntry{
		Filename: name,
		Longname: fmt.Sprintf("%s %4d %-8s %-8s %8d %s %5s %s", "-rw-r--r--", 1, "1000", "1000", shown, "Mar  4", "05:06", name),
		Attrs:    sftpwire.Attrs{Flags: sftpwire.AttrSize, Size: size},
	}
}

func TestWrongSizeRewritesTheSizeInALongname(t *testing.T) {
	const actual = 4096
	tests := []struct {
		name      string
		wrongSize sftpproxy.WrongSize
		longname  string
		want      string
	}{
		{
			name:      "pkg/sftp",
			wrongSize: sftpproxy.WrongSize{Size: 7},
			longname:  "-rw-r--r--    1 1000     1000         4096 Mar  4 05:06 f",
			want:      "-rw-r--r--    1 1000     1000            7 Mar  4 05:06 f",
		},
		{
			name:      "OpenSSH",
			wrongSize: sftpproxy.WrongSize{Delta: 1 << 20},
			longname:  "-rw-r--r--   1 gb       staff        4096 Mar  4 05:06 f",
			want:      "-rw-r--r--   1 gb       staff     1052672 Mar  4 05:06 f",
		},
		{
			name:      "wider than its column",
			wrongSize: sftpproxy.WrongSize{Size: 1 << 40},
			longname:  "-rw-r--r--    1 1000     1000         4096 Mar  4 05:06 f",
			want:      "-rw-r--r--    1 1000     1000 1099511627776 Mar  4 05:06 f",
		},
		{
			name:      "a name with spaces",
			wrongSize: sftpproxy.WrongSize{Size: 7},
			longname:  "-rw-r--r--    1 1000     1000         4096 Mar  4 05:06 my  4096 f",
			want:      "-rw-r--r--    1 1000     1000            7 Mar  4 05:06 my  4096 f",
		},
		{
			name:      "another size shown",
			wrongSize: sftpproxy.WrongSize{Size: 7},
			longname:  "-rw-r--r--    1 1000     1000         4095 Mar  4 05:06 f",
			want:      "-rw-r--r--    1 1000     1000         4095 Mar  4 05:06 f",
		},
		{
			name:      "too few fields",
			wrongSize: sftpproxy.WrongSize{Size: 7},
			longname:  "-rw-r--r-- 1 1000 1000",
			want:      "-rw-r--r-- 1 1000 1000",
		},
		{
			name:      "no longname",
			wrongSize: sftpproxy.WrongSize{Size: 7},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p, fb := startProxyOnFake(t, sftpproxy.Options{
					Faults: func(r sftpproxy.Request) sftpproxy.Action {
						if r.Entry {
							return tt.wrongSize
						}
						return nil
					},
				})
				openDir(t, p, fb, "/d")

				entry := sftpwire.NameEntry{Filename: "f", Longname: tt.longname, Attrs: sftpwire.Attrs{Flags: sftpwire.AttrSize, Size: actual}}
				p.client.send(t, 2, &sftpwire.ReadDir{Handle: "h"})
				fb.reply(t, fb.next(t).id, &sftpwire.NameReply{Entries: []sftpwire.NameEntry{entry}})
				_, reply := p.client.receiveReply(t)
				if name, ok := reply.(*sftpwire.NameReply); !ok || len(name.Entries) != 1 || name.Entries[0].Longname != tt.want {
					t.Errorf("reply = %#v, want the longname %q", reply, tt.want)
				}
			})
		})
	}
}

func TestOnlyAWrongSizeAppliesToAReaddirEntry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, fb := startProxyOnFake(t, sftpproxy.Options{
			Faults: func(r sftpproxy.Request) sftpproxy.Action {
				if r.Entry {
					return sftpproxy.Delay{Duration: time.Second}
				}
				return nil
			},
		})
		openDir(t, p, fb, "/d")

		p.client.send(t, 2, &sftpwire.ReadDir{Handle: "h"})
		fb.reply(t, fb.next(t).id, &sftpwire.NameReply{Entries: []sftpwire.NameEntry{lsEntry("f", 1, 1)}})
		p.client.assertClosed(t)
		want := "a sftpproxy.Delay fault cannot apply to a READDIR entry"
		if err := p.result.wait(t); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Serve = %v, want an error containing %q", err, want)
		}
	})
}

func openDir(t *testing.T, p *proxy, fb *fakeBackend, dir string) {
	t.Helper()
	p.client.send(t, 1, &sftpwire.OpenDir{Path: dir})
	fb.reply(t, fb.next(t).id, &sftpwire.HandleReply{Handle: "h"})
	p.client.assertReplies(t, 1)
}
