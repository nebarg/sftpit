package sftpproxy_test

import (
	"slices"
	"strconv"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

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
					Logger: logs.logger(),
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
				logs.assertLogged(t, want)
			})
		})
	}
}
