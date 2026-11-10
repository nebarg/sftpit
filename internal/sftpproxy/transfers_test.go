package sftpproxy_test

import (
	"slices"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/nebarg/sftpit/internal/events"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

func TestTransfersCountAFileHandleUntilItsTransferIsRecorded(t *testing.T) {
	tests := []struct {
		name string
		end  func(t *testing.T, p *proxy, fb *fakeBackend)
		// counted is what Transfers counted as each transfer was recorded.
		counted []int64
	}{
		{"closed by the client", func(t *testing.T, p *proxy, fb *fakeBackend) {
			t.Helper()
			p.client.send(t, 2, &sftpwire.Close{Handle: "h"})
			fb.reply(t, fb.next(t).id, status(sftpwire.StatusOK))
			p.client.assertReplies(t, 2)
			p.client.conn.Close()
		}, []int64{1}},
		{"open as the session ends", func(_ *testing.T, p *proxy, _ *fakeBackend) {
			p.client.conn.Close()
		}, []int64{1}},
		// The backend may or may not have closed the file, so the session
		// records no transfer, but must not leave the handle counted.
		{"closing as the session ends", func(t *testing.T, p *proxy, fb *fakeBackend) {
			t.Helper()
			p.client.send(t, 2, &sftpwire.Close{Handle: "h"})
			fb.next(t)
			p.client.conn.Close()
		}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var transfers sftpproxy.Transfers
				var mu sync.Mutex
				var counted []int64
				p, fb := startProxyOnFake(t, sftpproxy.Options{Transfers: &transfers, Record: func(e events.Event) {
					if e.Kind == events.Transfer {
						mu.Lock()
						defer mu.Unlock()
						counted = append(counted, transfers.Open())
					}
				}})
				openForUpload(t, p, fb, "h")
				if got := transfers.Open(); got != 1 {
					t.Errorf("with a file open, Transfers counts %d, want 1", got)
				}

				tt.end(t, p, fb)
				_ = p.result.wait(t)
				mu.Lock()
				defer mu.Unlock()
				if !slices.Equal(counted, tt.counted) {
					t.Errorf("as each transfer was recorded, Transfers counted %v, want %v", counted, tt.counted)
				}
				if got := transfers.Open(); got != 0 {
					t.Errorf("once the session ended, Transfers counts %d, want 0", got)
				}
			})
		})
	}
}

func TestTransfersCountsNeitherDirectoriesNorFailedOpens(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var transfers sftpproxy.Transfers
		p, fb := startProxyOnFake(t, sftpproxy.Options{Transfers: &transfers})
		p.client.send(t, 1, &sftpwire.OpenDir{Path: "/"})
		fb.reply(t, fb.next(t).id, &sftpwire.HandleReply{Handle: "d"})
		p.client.send(t, 2, &sftpwire.Open{Path: "/missing", Flags: sftpwire.OpenRead})
		fb.reply(t, fb.next(t).id, status(sftpwire.StatusNoSuchFile))
		p.client.assertReplies(t, 1, 2)
		if got := transfers.Open(); got != 0 {
			t.Errorf("Transfers counts %d, want 0", got)
		}
	})
}

// A session without a recorder still settles what it counted.
func TestTransfersSettleWithoutARecorder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var transfers sftpproxy.Transfers
		p, fb := startProxyOnFake(t, sftpproxy.Options{Transfers: &transfers})
		openForUpload(t, p, fb, "h")
		p.client.send(t, 2, &sftpwire.Close{Handle: "h"})
		fb.reply(t, fb.next(t).id, status(sftpwire.StatusOK))
		p.client.assertReplies(t, 2)
		if got := transfers.Open(); got != 0 {
			t.Errorf("after the CLOSE, Transfers counts %d, want 0", got)
		}
	})
}
