package sftpproxy_test

import (
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

func TestListenerDownClosingEveryConnectionEndsTheSessionAsADrop(t *testing.T) {
	for _, when := range []sftpproxy.When{sftpproxy.Before, sftpproxy.After} {
		t.Run(when.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var logs syncBuffer
				down := sftpproxy.ListenerDown{When: when, Duration: 5 * time.Second, CloseExisting: true}
				p, fb := startProxyOnFake(t, sftpproxy.Options{Faults: onPath("/a", down), Logger: slog.New(slog.NewTextHandler(&logs, nil))})
				p.client.sendTogether(t,
					&sftpwire.Stat{Path: "/first"},
					&sftpwire.Rename{OldPath: "/a", NewPath: "/b"},
					&sftpwire.Stat{Path: "/last"},
				)

				first := fb.next(t)
				if when == sftpproxy.After {
					rename := fb.next(t)
					fb.reply(t, rename.id, &sftpwire.StatusReply{Code: sftpwire.StatusOK})
				}
				fb.assertNoRequest(t)
				if got := p.conn.events(); len(got) != 0 {
					t.Fatalf("connection events %v before the earlier reply was written", got)
				}

				fb.reply(t, first.id, &sftpwire.AttrsReply{})
				p.client.assertReplies(t, 1)
				p.client.assertClosed(t)
				if err := p.result.wait(t); err != nil {
					t.Errorf("Serve = %v, want nil", err)
				}
				if got, want := p.conn.events(), []string{"down 5s, closing every connection"}; !slices.Equal(got, want) {
					t.Errorf("connection events = %v, want %v", got, want)
				}
				fb.assertNoRequest(t)
				if want := `msg="injected fault" request=SSH_FXP_RENAME path=/a target=/b fault=listener_down when=` + when.String() + ` duration=5s close_existing=true`; !strings.Contains(logs.String(), want) {
					t.Errorf("logs lack %s:\n%s", want, logs.String())
				}
			})
		})
	}
}

func TestListenerDownLeavingConnectionsOpenLetsTheSessionCarryOn(t *testing.T) {
	for _, when := range []sftpproxy.When{sftpproxy.Before, sftpproxy.After} {
		t.Run(when.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				down := sftpproxy.ListenerDown{When: when, Duration: 5 * time.Second}
				p, fb := startProxyOnFake(t, sftpproxy.Options{Faults: onPath("/a", down)})
				p.client.send(t, 1, &sftpwire.Rename{OldPath: "/a", NewPath: "/b"})

				rename := fb.next(t)
				synctest.Wait()
				wantBefore := []string{"down 5s"}
				if when == sftpproxy.After {
					wantBefore = nil
				}
				if got := p.conn.events(); !slices.Equal(got, wantBefore) {
					t.Errorf("connection events as the backend got the rename = %v, want %v", got, wantBefore)
				}
				fb.reply(t, rename.id, &sftpwire.StatusReply{Code: sftpwire.StatusOK})
				p.client.assertStatus(t, 1, sftpwire.StatusOK, "")

				p.client.send(t, 2, &sftpwire.Stat{Path: "/b"})
				stat := fb.next(t)
				fb.reply(t, stat.id, &sftpwire.AttrsReply{})
				p.client.assertReplies(t, 2)
				if got := p.conn.events(); !slices.Equal(got, []string{"down 5s"}) {
					t.Errorf("connection events = %v, want [down 5s]", got)
				}
			})
		})
	}
}

func TestListenerDownAtAMoment(t *testing.T) {
	tests := []struct {
		name   string
		down   sftpproxy.ListenerDown
		closed bool
		events []string
	}{
		{"closing every connection", sftpproxy.ListenerDown{Duration: 5 * time.Second, CloseExisting: true}, true, []string{"down 5s, closing every connection"}},
		{"leaving connections open", sftpproxy.ListenerDown{Duration: 5 * time.Second}, false, []string{"down 5s"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var logs syncBuffer
				start := time.Now()
				p, fb := startProxyOnFake(t, sftpproxy.Options{
					Timers: []sftpproxy.Timer{{At: start.Add(2 * time.Second), Action: tt.down}},
					Logger: slog.New(slog.NewTextHandler(&logs, nil)),
				})
				time.Sleep(2 * time.Second)
				synctest.Wait()
				if got := p.conn.events(); !slices.Equal(got, tt.events) {
					t.Errorf("connection events = %v, want %v", got, tt.events)
				}
				if tt.closed {
					p.client.assertClosed(t)
				} else {
					p.client.send(t, 1, &sftpwire.Stat{Path: "/f"})
					stat := fb.next(t)
					fb.reply(t, stat.id, &sftpwire.AttrsReply{})
					p.client.assertReplies(t, 1)
				}
				want := `msg="injected fault" fault=listener_down when=timer duration=5s close_existing=` + strconv.FormatBool(tt.closed)
				if !strings.Contains(logs.String(), want) {
					t.Errorf("logs lack %s:\n%s", want, logs.String())
				}
			})
		})
	}
}
