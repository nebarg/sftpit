package sftpproxy_test

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

// snapshotTime is how long each snapshot takes in these tests, as it might
// for a large file.
const snapshotTime = time.Second

var failAtCutoff = sftpproxy.PartialUpload{Cutoff: cutoff, Result: sftpproxy.Fail{Status: sftpwire.StatusFailure}}

func TestSnapshotAtCloseHoldsBackTheReplyAndTheFile(t *testing.T) {
	for _, order := range replyOrders {
		t.Run(order.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var logs syncBuffer
				var snaps snapshots
				p, fb := startProxyOnFake(t, sftpproxy.Options{
					Faults:     inSequence(failAtCutoff),
					ReplyOrder: order,
					Snapshot:   snaps.take,
					Logger:     slog.New(slog.NewTextHandler(&logs, nil)),
				})
				openForUpload(t, p, fb, "h")
				cutWrite(t, p, fb, "h")

				start := time.Now()
				// The client retries at once, truncating the file.
				p.client.sendTogether(t, &sftpwire.Close{Handle: "h"}, &sftpwire.Open{Path: "/f", Flags: sftpwire.OpenWrite | sftpwire.OpenTruncate})
				closeReq := fb.next(t)
				if _, ok := closeReq.packet.(*sftpwire.Close); !ok {
					t.Fatalf("backend received %#v, want the CLOSE", closeReq.packet)
				}
				fb.reply(t, closeReq.id, status(sftpwire.StatusOK))
				fb.assertNoRequest(t)
				p.client.assertReplies(t, 1)
				if got := time.Since(start); got != snapshotTime {
					t.Errorf("client received the CLOSE reply after %v, want it once the file was snapshotted, after %v", got, snapshotTime)
				}

				retry := fb.next(t)
				if open, ok := retry.packet.(*sftpwire.Open); !ok || open.Path != "/f" {
					t.Fatalf("backend received %#v, want the retry's OPEN", retry.packet)
				}
				fb.reply(t, retry.id, &sftpwire.HandleReply{Handle: "h2"})
				p.client.assertReplies(t, 2)
				if got := snaps.taken(); !slices.Equal(got, []string{"/f"}) {
					t.Errorf("snapshots of %v, want one of /f", got)
				}
				assertSnapshotsLogged(t, logs.String(), snapshotLog("/f", "client"))
			})
		})
	}
}

// TestSnapshotHoldsBackOtherFilesInRequestOrderOnly checks that a snapshot
// at close holds back a request on another file just as a slow CLOSE would:
// in request order only.
func TestSnapshotHoldsBackOtherFilesInRequestOrderOnly(t *testing.T) {
	for _, order := range replyOrders {
		t.Run(order.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var snaps snapshots
				p, fb := startProxyOnFake(t, sftpproxy.Options{
					Faults:     inSequence(failAtCutoff),
					ReplyOrder: order,
					Snapshot:   snaps.take,
				})
				openForUpload(t, p, fb, "h")
				cutWrite(t, p, fb, "h")

				start := time.Now()
				p.client.send(t, 1, &sftpwire.Close{Handle: "h"})
				fb.reply(t, fb.next(t).id, status(sftpwire.StatusOK))
				p.client.send(t, 2, &sftpwire.Stat{Path: "/other"})
				stat := fb.next(t)
				assertPaths(t, []backendRequest{stat}, "/other")
				want := snapshotTime
				if order == sftpproxy.CompletionOrder {
					want = 0
				}
				if got := time.Since(start); got != want {
					t.Errorf("backend received the STAT after %v, want %v", got, want)
				}
				fb.reply(t, stat.id, &sftpwire.AttrsReply{})
				p.client.assertReplies(t, 1, 2)
			})
		})
	}
}

// TestSnapshotOnceWhenTheClientClosesTwice closes a faulted handle twice, as
// phpseclib does after a failed upload. A delayed write holds back the first
// CLOSE, so in completion order the second arrives while the handle is still
// open.
func TestSnapshotOnceWhenTheClientClosesTwice(t *testing.T) {
	for _, order := range replyOrders {
		t.Run(order.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var logs syncBuffer
				var snaps snapshots
				p, fb := startProxyOnFake(t, sftpproxy.Options{
					Faults:     on[*sftpwire.Write](sftpproxy.Delay{When: sftpproxy.Before, Duration: time.Second}),
					ReplyOrder: order,
					Snapshot:   snaps.take,
					Logger:     slog.New(slog.NewTextHandler(&logs, nil)),
				})
				openForUpload(t, p, fb, "h")
				p.client.sendTogether(t, write("h", 0, 10), &sftpwire.Close{Handle: "h"}, &sftpwire.Close{Handle: "h"})

				fb.reply(t, fb.next(t).id, status(sftpwire.StatusOK))
				fb.reply(t, fb.next(t).id, status(sftpwire.StatusOK))
				fb.reply(t, fb.next(t).id, status(sftpwire.StatusFailure))
				p.client.assertReplies(t, 1, 2, 3)
				assertSnapshotsLogged(t, logs.String(), snapshotLog("/f", "client"))
			})
		})
	}
}

func TestSnapshotComesBeforeTheDrop(t *testing.T) {
	results := []struct {
		name   string
		result sftpproxy.Action
		events []string
	}{
		{name: "FIN", result: sftpproxy.Drop{}, events: []string{"close"}},
		{name: "RST", result: sftpproxy.Drop{Reset: true}, events: []string{"reset"}},
		{name: "freeze", result: sftpproxy.Freeze{Limit: time.Hour, Release: closed()}, events: []string{"freeze", "close"}},
	}

	for _, order := range replyOrders {
		for _, r := range results {
			t.Run(order.String()+"/"+r.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					var logs syncBuffer
					var snaps snapshots
					var p *proxy
					var fb *fakeBackend
					var eventsAtSnapshot []string
					p, fb = startProxyOnFake(t, sftpproxy.Options{
						Faults:     inSequence(sftpproxy.PartialUpload{Cutoff: cutoff, Result: r.result}),
						ReplyOrder: order,
						Snapshot: func(path string) (sftpproxy.Snapshot, error) {
							eventsAtSnapshot = p.conn.events()
							return snaps.take(path)
						},
						Logger: slog.New(slog.NewTextHandler(&logs, nil)),
					})
					openForUpload(t, p, fb, "h")
					p.client.send(t, 2, write("h", 50, 60))
					fb.reply(t, fb.next(t).id, status(sftpwire.StatusOK))

					p.client.assertClosed(t)
					if err := p.result.wait(t); err != nil {
						t.Errorf("Serve after a drop = %v, want nil", err)
					}
					if len(eventsAtSnapshot) != 0 {
						t.Errorf("connection %v before the snapshot, want it untouched", eventsAtSnapshot)
					}
					if got := p.conn.events(); !slices.Equal(got, r.events) {
						t.Errorf("connection events = %v, want %v", got, r.events)
					}
					assertSnapshotsLogged(t, logs.String(), snapshotLog("/f", "fault"))
				})
			})
		}
	}
}

func TestSnapshotWhenTheSessionEnds(t *testing.T) {
	tests := []struct {
		name string
		end  func(t *testing.T, p *proxy, fb *fakeBackend)
	}{
		{
			name: "client disconnects",
			end:  func(t *testing.T, p *proxy, fb *fakeBackend) { p.client.conn.Close() },
		},
		{
			name: "cancelled before the backend closes the handle",
			end: func(t *testing.T, p *proxy, fb *fakeBackend) {
				p.client.send(t, 1, &sftpwire.Close{Handle: "h"})
				fb.next(t)
				p.cancel()
			},
		},
	}

	for _, order := range replyOrders {
		for _, tt := range tests {
			t.Run(order.String()+"/"+tt.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					var logs syncBuffer
					var snaps snapshots
					p, fb := startProxyOnFake(t, sftpproxy.Options{
						Faults:     inSequence(failAtCutoff),
						ReplyOrder: order,
						Snapshot:   snaps.take,
						Logger:     slog.New(slog.NewTextHandler(&logs, nil)),
					})
					openForUpload(t, p, fb, "h")
					cutWrite(t, p, fb, "h")

					tt.end(t, p, fb)
					p.result.wait(t)
					assertSnapshotsLogged(t, logs.String(), snapshotLog("/f", `"session end"`))
				})
			})
		}
	}
}

func TestSnapshotsOnlyFaultedFileHandles(t *testing.T) {
	tests := []struct {
		name   string
		faults func(sftpproxy.Request) sftpproxy.Action
		dir    bool
		noHook bool
		// closedBy holds how each snapshot logged says its handle was
		// closed.
		closedBy []string
	}{
		{name: "no fault", faults: func(sftpproxy.Request) sftpproxy.Action { return nil }},
		{
			name:   "cutoff not reached",
			faults: on[*sftpwire.Open](sftpproxy.PartialUpload{Cutoff: 10, Result: sftpproxy.Drop{}}),
		},
		{
			name:     "cutoff reached",
			faults:   on[*sftpwire.Open](sftpproxy.PartialUpload{Cutoff: 5, Result: sftpproxy.Fail{Status: sftpwire.StatusFailure}}),
			closedBy: []string{"client"},
		},
		{
			name:     "fault on the open",
			faults:   on[*sftpwire.Open](sftpproxy.Delay{When: sftpproxy.After, Duration: time.Second}),
			closedBy: []string{"client"},
		},
		{
			name:     "fault on a write",
			faults:   on[*sftpwire.Write](sftpproxy.Delay{When: sftpproxy.Before, Duration: time.Second}),
			closedBy: []string{"client"},
		},
		{
			name:     "fault on the close",
			faults:   on[*sftpwire.Close](sftpproxy.Fail{When: sftpproxy.After, Status: sftpwire.StatusFailure}),
			closedBy: []string{"client"},
		},
		{
			// The backend still has the handle open until the session ends.
			name:     "close failed before the backend",
			faults:   on[*sftpwire.Close](sftpproxy.Fail{When: sftpproxy.Before, Status: sftpwire.StatusFailure}),
			closedBy: []string{`"session end"`},
		},
		{
			name: "directory",
			dir:  true,
			faults: func(sftpproxy.Request) sftpproxy.Action {
				return sftpproxy.Delay{When: sftpproxy.After, Duration: time.Second}
			},
		},
		{
			name:   "without a Snapshot",
			faults: on[*sftpwire.Open](sftpproxy.PartialUpload{Cutoff: 5, Result: sftpproxy.Fail{Status: sftpwire.StatusFailure}}),
			noHook: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var logs syncBuffer
				var snaps snapshots
				opts := sftpproxy.Options{
					Faults:   tt.faults,
					Snapshot: snaps.take,
					Logger:   slog.New(slog.NewTextHandler(&logs, nil)),
				}
				if tt.noHook {
					opts.Snapshot = nil
				}
				p, fb := startProxyOnFake(t, opts)
				go fb.answerAll()

				var open, use sftpwire.Packet = &sftpwire.Open{Path: "/f", Flags: sftpwire.OpenWrite | sftpwire.OpenCreate}, write("h", 0, 10)
				if tt.dir {
					open, use = &sftpwire.OpenDir{Path: "/f"}, &sftpwire.ReadDir{Handle: "h"}
				}
				for i, req := range []sftpwire.Packet{open, use, &sftpwire.Close{Handle: "h"}} {
					p.client.send(t, uint32(i), req)
					p.client.assertReplies(t, uint32(i))
				}
				p.client.conn.Close()
				p.result.wait(t)

				var want []string
				for _, by := range tt.closedBy {
					want = append(want, snapshotLog("/f", by))
				}
				assertSnapshotsLogged(t, logs.String(), want...)
			})
		})
	}
}

func TestSnapshotFailureIsLoggedAndTheCloseSucceeds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs syncBuffer
		p, fb := startProxyOnFake(t, sftpproxy.Options{
			Faults: inSequence(failAtCutoff),
			Snapshot: func(string) (sftpproxy.Snapshot, error) {
				return sftpproxy.Snapshot{}, errors.New("file vanished")
			},
			Logger: slog.New(slog.NewTextHandler(&logs, nil)),
		})
		openForUpload(t, p, fb, "h")
		cutWrite(t, p, fb, "h")

		p.client.send(t, 1, &sftpwire.Close{Handle: "h"})
		fb.reply(t, fb.next(t).id, status(sftpwire.StatusOK))
		p.client.assertStatus(t, 1, sftpwire.StatusOK, "Success")
		want := `level=ERROR msg="snapshot failed" path=/f closed_by=client err="file vanished"`
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log does not contain %q:\n%s", want, logs.String())
		}
	})
}

// snapshots is a Snapshot hook that records the paths it is called with.
// Each snapshot takes snapshotTime.
type snapshots struct {
	mu    sync.Mutex
	paths []string
}

func (s *snapshots) take(path string) (sftpproxy.Snapshot, error) {
	time.Sleep(snapshotTime)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.paths = append(s.paths, path)
	return snapshotOf(path), nil
}

func (s *snapshots) taken() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.paths)
}

// snapshotOf is the snapshot that snapshots gives the file at path.
func snapshotOf(path string) sftpproxy.Snapshot {
	return sftpproxy.Snapshot{Size: cutoff, SHA256: sha256.Sum256([]byte(path))}
}

// snapshotLog is the log line for snapshotOf(path), closed as closedBy says,
// quoted as the log quotes it.
func snapshotLog(path, closedBy string) string {
	snap := snapshotOf(path)
	return fmt.Sprintf("level=INFO msg=snapshot path=%s closed_by=%s size=%d sha256=%x", path, closedBy, snap.Size, snap.SHA256)
}

// assertSnapshotsLogged checks that logs has exactly the snapshot lines in
// want.
func assertSnapshotsLogged(t *testing.T, logs string, want ...string) {
	t.Helper()
	var got []string
	for line := range strings.Lines(logs) {
		if strings.Contains(line, "msg=snapshot") {
			_, after, _ := strings.Cut(strings.TrimSpace(line), " ")
			got = append(got, after)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("snapshots logged:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// cutWrite sends a write on handle that crosses the cutoff as request 2,
// and has the backend store what reaches it.
func cutWrite(t *testing.T, p *proxy, fb *fakeBackend, handle string) {
	t.Helper()
	p.client.send(t, 2, write(handle, 50, 60))
	fb.reply(t, fb.next(t).id, status(sftpwire.StatusOK))
	p.client.assertStatus(t, 2, sftpwire.StatusFailure, "Failure")
}

// answerAll answers every request the backend receives until the session
// ends: an OPEN or OPENDIR with handle "h", a READDIR with EOF and anything
// else with success.
func (fb *fakeBackend) answerAll() {
	for req := range fb.requests {
		var reply sftpwire.Packet = status(sftpwire.StatusOK)
		switch req.packet.(type) {
		case *sftpwire.Open, *sftpwire.OpenDir:
			reply = &sftpwire.HandleReply{Handle: "h"}
		case *sftpwire.ReadDir:
			reply = status(sftpwire.StatusEOF)
		}
		if _, err := fb.conn.Write(sftpwire.AppendPacket(nil, req.id, reply)); err != nil {
			return
		}
	}
}

// on returns faults that apply action to every request of type P.
func on[P sftpwire.Packet](action sftpproxy.Action) func(sftpproxy.Request) sftpproxy.Action {
	return func(r sftpproxy.Request) sftpproxy.Action {
		if _, ok := r.Packet.(P); ok {
			return action
		}
		return nil
	}
}

func closed() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}
