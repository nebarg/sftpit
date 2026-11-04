package sftpproxy_test

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nebarg/sftpit/internal/events"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

// recording keeps the events a session records.
type recording struct {
	mu     sync.Mutex
	events []events.Event
}

func (r *recording) record(e events.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

// summaries returns a line for each event recorded, as summary gives it,
// once the session's goroutines are idle: a reply's event is recorded just
// after the client can read the reply.
func (r *recording) summaries() []string {
	synctest.Wait()
	r.mu.Lock()
	defer r.mu.Unlock()
	var lines []string
	for _, e := range r.events {
		lines = append(lines, summary(e))
	}
	return lines
}

// summary describes e in one line, with the fields that its kind sets.
func summary(e events.Event) string {
	parts := []string{string(e.Kind)}
	add := func(name, value string) {
		if value != "" {
			parts = append(parts, name+"="+value)
		}
	}
	add("request", e.Request)
	if e.RequestID != nil {
		add("id", strconv.FormatUint(uint64(*e.RequestID), 10))
	}
	add("path", e.Path)
	add("target", e.Target)
	add("reply", e.Reply)
	add("backend", e.BackendReply)
	add("rule", e.Rule)
	add("read_only", e.ReadOnly)
	add("reason", e.Reason)
	if f := e.Fault; f != nil {
		add("fault", f.Type)
		add("when", f.When)
		for _, k := range slices.Sorted(func(yield func(string) bool) {
			for k := range f.Settings {
				if !yield(k) {
					return
				}
			}
		}) {
			add(k, fmt.Sprint(f.Settings[k]))
		}
	}
	if t := e.Transfer; t != nil {
		parts = append(parts, fmt.Sprintf("%s reads=%d/%d writes=%d/%d end=%d closed=%s faulted=%v", t.Mode, t.Reads, t.BytesRead, t.Writes, t.BytesWritten, t.End, t.Closed, t.Faulted))
	}
	if s := e.Snapshot; s != nil {
		parts = append(parts, fmt.Sprintf("size=%d sha256=%s copy=%q", s.Size, s.SHA256, s.Copy))
	}
	return strings.Join(parts, " ")
}

func assertSummaries(t *testing.T, got []string, want ...string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("events:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

func TestEventsRecordEachRequestAndSumTransfers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var rec recording
		p := startProxy(t, inMemoryBackend(t), sftpproxy.Options{Record: rec.record})
		p.client.init(t, 3)

		p.client.send(t, 7, &sftpwire.Stat{Path: "/missing"})
		p.client.receiveReply(t)
		storeFile(t, p.client, "/f", make([]byte, 3*readSize+5))
		if got := readFile(t, p.client, "/f"); len(got) != 3*readSize+5 {
			t.Fatalf("read %d bytes back", len(got))
		}

		assertSummaries(t, rec.summaries(),
			"operation request=SSH_FXP_STAT id=7 path=/missing reply=SSH_FX_NO_SUCH_FILE backend=SSH_FX_NO_SUCH_FILE",
			"operation request=SSH_FXP_OPEN id=1 path=/f reply=SSH_FXP_HANDLE backend=SSH_FXP_HANDLE",
			fmt.Sprintf("transfer path=/f write reads=0/0 writes=4/%[1]d end=%[1]d closed=close faulted=false", 3*readSize+5),
			"operation request=SSH_FXP_CLOSE id=3 path=/f reply=SSH_FX_OK backend=SSH_FX_OK",
			"operation request=SSH_FXP_OPEN id=1 path=/f reply=SSH_FXP_HANDLE backend=SSH_FXP_HANDLE",
			fmt.Sprintf("transfer path=/f read reads=4/%[1]d writes=0/0 end=%[1]d closed=close faulted=false", 3*readSize+5),
			"operation request=SSH_FXP_CLOSE id=3 path=/f reply=SSH_FX_OK backend=SSH_FX_OK",
		)
	})
}

func TestEventsSumAHandleStillOpenAsItsSessionEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var rec recording
		p, fb := startProxyOnFake(t, sftpproxy.Options{Record: rec.record})
		openForDownload(t, p, fb)
		p.client.send(t, 2, &sftpwire.Read{Handle: "h", Offset: 0, Length: 10})
		fb.reply(t, fb.next(t).id, &sftpwire.DataReply{Data: make([]byte, 10)})
		p.client.assertReplies(t, 2)
		p.client.conn.Close()
		_ = p.result.wait(t)

		assertSummaries(t, rec.summaries(),
			"operation request=SSH_FXP_OPEN id=1 path=/f reply=SSH_FXP_HANDLE backend=SSH_FXP_HANDLE",
			"transfer path=/f read reads=1/10 writes=0/0 end=10 closed=session_ended faulted=false",
		)
	})
}

func TestEventsNameTheRuleOfEachFault(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var rec recording
		failure := sftpwire.StatusFailure
		p, fb := startProxyOnFake(t, sftpproxy.Options{
			Faults: func(r sftpproxy.Request) sftpproxy.Fault {
				switch r.Packet.(type) {
				case *sftpwire.Stat:
					return sftpproxy.Fault{Action: sftpproxy.Fail{When: sftpproxy.Before, Status: failure}, Rule: "deny"}
				case *sftpwire.LStat:
					return sftpproxy.Fault{Action: sftpproxy.Fail{When: sftpproxy.After, Status: failure}, Rule: "lie"}
				}
				return sftpproxy.Fault{}
			},
			Record: rec.record,
		})
		go fb.answerAll()
		p.client.send(t, 2, &sftpwire.Stat{Path: "/f"})
		p.client.assertStatus(t, 2, failure, "Failure")
		p.client.send(t, 3, &sftpwire.LStat{Path: "/f"})
		p.client.assertStatus(t, 3, failure, "Failure")
		p.client.send(t, 4, &sftpwire.Remove{Path: "/f"})
		p.client.assertReplies(t, 4)

		assertSummaries(t, rec.summaries(),
			"fault request=SSH_FXP_STAT id=2 path=/f rule=deny fault=fail when=before status=SSH_FX_FAILURE",
			"operation request=SSH_FXP_STAT id=2 path=/f reply=SSH_FX_FAILURE rule=deny",
			"fault request=SSH_FXP_LSTAT id=3 path=/f rule=lie fault=fail when=after status=SSH_FX_FAILURE",
			"operation request=SSH_FXP_LSTAT id=3 path=/f reply=SSH_FX_FAILURE backend=SSH_FXP_ATTRS rule=lie",
			"operation request=SSH_FXP_REMOVE id=4 path=/f reply=SSH_FX_OK backend=SSH_FX_OK",
		)
	})
}

func TestEventsRecordHowEachWaitEnds(t *testing.T) {
	stall := sftpproxy.Stall{When: sftpproxy.Before, Limit: time.Minute}
	tests := []struct {
		name   string
		action func(release <-chan struct{}) sftpproxy.Action
		// end ends the wait, through the fault's release, the session's
		// release of stalls, or the client, or nil to let it run its
		// course.
		end    func(release, released chan struct{}, p *proxy)
		reason string
	}{
		{
			name: "a delay that runs its course",
			action: func(release <-chan struct{}) sftpproxy.Action {
				return sftpproxy.Delay{Duration: time.Second, Release: release}
			},
			reason: "elapsed",
		},
		{
			name:   "a stall at its limit",
			action: func(release <-chan struct{}) sftpproxy.Action { s := stall; s.Release = release; return s },
			reason: "limit",
		},
		{
			name:   "a stall whose rule is removed",
			action: func(release <-chan struct{}) sftpproxy.Action { s := stall; s.Release = release; return s },
			end:    func(release, _ chan struct{}, _ *proxy) { close(release) },
			reason: "canceled",
		},
		{
			name:   "a stall released",
			action: func(release <-chan struct{}) sftpproxy.Action { s := stall; s.Release = release; return s },
			end:    func(_, released chan struct{}, _ *proxy) { close(released) },
			reason: "released",
		},
		{
			name:   "a stall whose session ends",
			action: func(release <-chan struct{}) sftpproxy.Action { s := stall; s.Release = release; return s },
			end:    func(_, _ chan struct{}, p *proxy) { p.cancel() },
			reason: "session_ended",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var rec recording
				release, released := make(chan struct{}), make(chan struct{})
				action := tt.action(release)
				p, fb := startProxyOnFake(t, sftpproxy.Options{
					Faults: func(sftpproxy.Request) sftpproxy.Fault {
						return sftpproxy.Fault{Action: action, Rule: "slow"}
					},
					Released: func() <-chan struct{} { return released },
					Record:   rec.record,
				})
				go fb.answerAll()
				p.client.send(t, 2, &sftpwire.Stat{Path: "/f"})
				synctest.Wait()
				if tt.end != nil {
					tt.end(release, released, p)
				} else {
					time.Sleep(time.Minute)
				}
				synctest.Wait()
				p.cancel()
				_ = p.result.wait(t)

				got := rec.summaries()
				var ended []string
				for _, line := range got {
					if strings.HasPrefix(line, "fault_ended") {
						ended = append(ended, line)
					}
				}
				want := fmt.Sprintf("fault_ended request=SSH_FXP_STAT id=2 path=/f rule=slow reason=%s fault=%s", tt.reason, faultName(action))
				if !slices.Equal(ended, []string{want}) {
					t.Errorf("events:\n  %s\nwant one %q", strings.Join(got, "\n  "), want)
				}
			})
		})
	}
}

// faultName names the type of a, as events give it.
func faultName(a sftpproxy.Action) string {
	return sftpproxy.FaultAttrs(a, "")[1].(string)
}

func TestEventsRecordTransferFaultsAndTheirEffects(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var rec recording
		var snaps snapshots
		p, fb := startProxyOnFake(t, sftpproxy.Options{
			Faults: func(r sftpproxy.Request) sftpproxy.Fault {
				if _, ok := r.Packet.(*sftpwire.Open); ok {
					return sftpproxy.Fault{Action: sftpproxy.PartialUpload{Cutoff: 100, Result: sftpproxy.Fail{Status: sftpwire.StatusFailure}}, Rule: "cut"}
				}
				return sftpproxy.Fault{}
			},
			Snapshot: snaps.take,
			Record:   rec.record,
		})
		openForUpload(t, p, fb, "h")
		p.client.send(t, 2, write("h", 0, 60))
		fb.reply(t, fb.next(t).id, status(sftpwire.StatusOK))
		p.client.assertReplies(t, 2)
		p.client.send(t, 3, write("h", 60, 60))
		fb.reply(t, fb.next(t).id, status(sftpwire.StatusOK))
		p.client.assertStatus(t, 3, sftpwire.StatusFailure, "Failure")
		p.client.send(t, 4, write("h", 120, 60))
		p.client.assertStatus(t, 4, sftpwire.StatusFailure, "Failure")
		p.client.send(t, 5, &sftpwire.Close{Handle: "h"})
		fb.reply(t, fb.next(t).id, status(sftpwire.StatusOK))
		p.client.assertReplies(t, 5)

		// The first write to reach the cutoff is the fault; the next is one
		// of its effects.
		assertSummaries(t, rec.summaries(),
			"operation request=SSH_FXP_OPEN id=1 path=/f reply=SSH_FXP_HANDLE backend=SSH_FXP_HANDLE",
			"fault request=SSH_FXP_WRITE id=3 path=/f rule=cut fault=fail when=after cutoff=100 offset=60 status=SSH_FX_FAILURE",
			"operation request=SSH_FXP_WRITE id=3 path=/f reply=SSH_FX_FAILURE backend=SSH_FX_OK rule=cut",
			"operation request=SSH_FXP_WRITE id=4 path=/f reply=SSH_FX_FAILURE rule=cut",
			fmt.Sprintf("snapshot path=/f reason=client size=%d sha256=%x copy=\"\"", cutoff, snapshotOf("/f").SHA256),
			"transfer path=/f rule=cut write reads=0/0 writes=2/100 end=100 closed=close faulted=true",
			"operation request=SSH_FXP_CLOSE id=5 path=/f reply=SSH_FX_OK backend=SSH_FX_OK",
		)
	})
}

func TestEventsRecordPolicyRefusalsAndTimers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var rec recording
		start := time.Now()
		p, fb := startProxyOnFake(t, sftpproxy.Options{
			ReadOnly: []string{"/reference"},
			Timers:   []sftpproxy.Timer{{At: start.Add(time.Minute), Action: sftpproxy.Drop{}, Rule: "hang-up"}},
			Record:   rec.record,
		})
		p.client.send(t, 2, &sftpwire.Remove{Path: "/reference/rates.csv"})
		p.client.assertStatus(t, 2, sftpwire.StatusPermissionDenied, "Permission denied")
		fb.assertNoRequest(t)
		time.Sleep(time.Minute)
		p.client.assertClosed(t)

		assertSummaries(t, rec.summaries(),
			"operation request=SSH_FXP_REMOVE id=2 path=/reference/rates.csv reply=SSH_FX_PERMISSION_DENIED read_only=/reference",
			"fault rule=hang-up fault=close_connection when=timer mode=fin",
		)
	})
}
