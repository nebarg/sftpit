package sftpproxy_test

import (
	"slices"
	"testing"
	"testing/synctest"

	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

func TestHideAnswersNoSuchFileWithoutTheBackend(t *testing.T) {
	tests := []struct {
		request sftpwire.Packet
		// logged is how the fault's log line names the request and its
		// paths.
		logged string
	}{
		{&sftpwire.Open{Path: "/f", Flags: sftpwire.OpenRead}, "request=SSH_FXP_OPEN path=/f"},
		{&sftpwire.Stat{Path: "/f"}, "request=SSH_FXP_STAT path=/f"},
		{&sftpwire.LStat{Path: "/f"}, "request=SSH_FXP_LSTAT path=/f"},
		{&sftpwire.Remove{Path: "/f"}, "request=SSH_FXP_REMOVE path=/f"},
		{&sftpwire.Rename{OldPath: "/f", NewPath: "/g"}, "request=SSH_FXP_RENAME path=/f target=/g"},
		{&sftpwire.PosixRename{OldPath: "/f", NewPath: "/g"}, "request=posix-rename@openssh.com path=/f target=/g"},
	}
	for _, tt := range tests {
		t.Run(tt.logged, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var logs syncBuffer
				p, fb := startProxyOnFake(t, sftpproxy.Options{
					Faults: onPath("/f", sftpproxy.Hide{}),
					Logger: logs.logger(),
				})

				p.client.send(t, 1, tt.request)
				p.client.assertStatus(t, 1, sftpwire.StatusNoSuchFile, "No such file")
				fb.assertNoRequest(t)
				logs.assertOnlyFault(t, `level=INFO msg="injected fault" `+tt.logged+` fault=hide when=before`)
			})
		})
	}
}

func TestHideRefusesRequestsThatNameNoFile(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, _ := startProxyOnFake(t, sftpproxy.Options{Faults: on[*sftpwire.Mkdir](sftpproxy.Hide{})})

		p.client.send(t, 1, &sftpwire.Mkdir{Path: "/d"})
		p.client.assertClosed(t)
		if err := p.result.wait(t); err == nil {
			t.Error("Serve returned nil for a Hide on MKDIR, want an error")
		}
	})
}

// TestHideLeavesOutTheReaddirEntriesFaultsChooses would hide . and .. too,
// if Faults were asked about them.
func TestHideLeavesOutTheReaddirEntriesFaultsChooses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs syncBuffer
		p, fb := startProxyOnFake(t, sftpproxy.Options{
			Faults: faultsOf(func(r sftpproxy.Request) sftpproxy.Action {
				switch {
				case r.Entry && (r.Path == "/d/b.csv" || r.Path == "/d" || r.Path == "/"):
					return sftpproxy.Hide{}
				case r.Entry && r.Path == "/d/c.csv":
					return sftpproxy.WrongSize{Delta: -1024}
				}
				return nil
			}),
			Logger: logs.logger(),
		})
		openDir(t, p, fb)

		p.client.send(t, 2, &sftpwire.ReadDir{Handle: "h"})
		fb.reply(t, fb.next(t).id, &sftpwire.NameReply{Entries: []sftpwire.NameEntry{
			lsEntry(".", 4096, 4096), lsEntry("..", 4096, 4096),
			lsEntry("a.csv", 4096, 4096), lsEntry("b.csv", 4096, 4096), lsEntry("c.csv", 4096, 4096),
		}})
		want := &sftpwire.NameReply{Entries: []sftpwire.NameEntry{
			lsEntry(".", 4096, 4096), lsEntry("..", 4096, 4096),
			lsEntry("a.csv", 4096, 4096), lsEntry("c.csv", 3072, 3072),
		}}
		if id, reply := p.client.receiveReply(t); id != 2 || !equalReplies(reply, want) {
			t.Errorf("reply = %d %#v, want 2 %#v", id, reply, want)
		}
		logs.assertLogged(t, `msg="injected fault" request=SSH_FXP_READDIR path=/d/b.csv fault=hide`)
	})
}

func TestHideReadsOnPastAReplyWhoseEveryEntryItLeavesOut(t *testing.T) {
	for _, order := range []sftpproxy.ReplyOrder{sftpproxy.RequestOrder, sftpproxy.CompletionOrder} {
		t.Run(order.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p, fb := startProxyOnFake(t, sftpproxy.Options{
					Faults: faultsOf(func(r sftpproxy.Request) sftpproxy.Action {
						if r.Entry && r.Path != "/d/c.csv" {
							return sftpproxy.Hide{}
						}
						return nil
					}),
					ReplyOrder: order,
				})
				openDir(t, p, fb)

				// The client sees neither the reply that holds only hidden
				// entries nor a reply with none.
				p.client.send(t, 2, &sftpwire.ReadDir{Handle: "h"})
				fb.reply(t, fb.next(t).id, &sftpwire.NameReply{Entries: []sftpwire.NameEntry{lsEntry("a.csv", 1, 1), lsEntry("b.csv", 1, 1)}})
				again := fb.next(t)
				if !equalReplies(again.packet, &sftpwire.ReadDir{Handle: "h"}) {
					t.Fatalf("backend received %#v, want the READDIR again", again.packet)
				}
				fb.reply(t, again.id, &sftpwire.NameReply{Entries: []sftpwire.NameEntry{lsEntry("c.csv", 1, 1)}})
				want := &sftpwire.NameReply{Entries: []sftpwire.NameEntry{lsEntry("c.csv", 1, 1)}}
				if id, reply := p.client.receiveReply(t); id != 2 || !equalReplies(reply, want) {
					t.Errorf("reply = %d %#v, want 2 %#v", id, reply, want)
				}

				// Hidden entries at the end of the directory give the
				// client the backend's EOF.
				p.client.send(t, 3, &sftpwire.ReadDir{Handle: "h"})
				fb.reply(t, fb.next(t).id, &sftpwire.NameReply{Entries: []sftpwire.NameEntry{lsEntry("d.csv", 1, 1)}})
				fb.reply(t, fb.next(t).id, status(sftpwire.StatusEOF))
				p.client.assertStatus(t, 3, sftpwire.StatusEOF, "End of file")

				// The backend's own empty reply passes through as it is.
				p.client.send(t, 4, &sftpwire.ReadDir{Handle: "h"})
				fb.reply(t, fb.next(t).id, &sftpwire.NameReply{})
				if id, reply := p.client.receiveReply(t); id != 4 || !equalReplies(reply, &sftpwire.NameReply{}) {
					t.Errorf("reply = %d %#v, want 4 with no entries", id, reply)
				}
				fb.assertNoRequest(t)
			})
		})
	}
}

func TestHideAnswersEOFRatherThanReadOnPastADrop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, fb := startProxyOnFake(t, sftpproxy.Options{
			Faults: faultsOf(func(r sftpproxy.Request) sftpproxy.Action {
				switch {
				case r.Entry:
					return sftpproxy.Hide{}
				case r.Path == "/f":
					return sftpproxy.Drop{}
				}
				return nil
			}),
		})
		openDir(t, p, fb)

		p.client.sendTogether(t, &sftpwire.ReadDir{Handle: "h"}, &sftpwire.Stat{Path: "/f"})
		readdir := fb.next(t)
		// Once everything waits, the drop has stopped forwarding.
		synctest.Wait()
		fb.reply(t, readdir.id, &sftpwire.NameReply{Entries: []sftpwire.NameEntry{lsEntry("a.csv", 1, 1)}})
		p.client.assertStatus(t, 1, sftpwire.StatusEOF, "End of file")
		p.client.assertClosed(t)
		fb.assertNoRequest(t)
		if got := p.conn.events(); !slices.Equal(got, []string{"close"}) {
			t.Errorf("connection events = %q, want a close", got)
		}
	})
}
