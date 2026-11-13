package activity

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/events"
)

var start = time.Date(2026, 11, 12, 10, 42, 0, 0, time.UTC)

// numbered numbers evs from 1, a second apart.
func numbered(evs ...events.Event) []events.Event {
	for i := range evs {
		evs[i].ID = uint64(i + 1)
		evs[i].Time = start.Add(time.Duration(i) * time.Second)
	}
	return evs
}

// op is a request of connection 1.
func op(id uint32, request, path, reply string) events.Event {
	return events.Event{Kind: events.Operation, Connection: 1, User: "test", Request: request, RequestID: &id, Path: path, Reply: reply}
}

func faulted(e events.Event, rule string) events.Event {
	e.Rule = rule
	return e
}

func fault(conn uint64, id uint32, request, path, rule, typ string) events.Event {
	e := events.Event{Kind: events.FaultInjected, Connection: conn, User: "test", Request: request, Path: path, Rule: rule, Fault: &events.Fault{Type: typ}}
	if id != 0 {
		e.RequestID = &id
	}
	return e
}

// open, transfer and login are events of connection 1.
func open(id uint32, path, mode string) events.Event {
	e := op(id, "SSH_FXP_OPEN", path, "SSH_FXP_HANDLE")
	e.Mode = mode
	return e
}

func transfer(path string, t events.Totals) events.Event {
	return events.Event{Kind: events.Transfer, Connection: 1, User: "test", Path: path, Transfer: &t}
}

func login() []events.Event {
	return []events.Event{
		{Kind: events.Connected, Connection: 1, Remote: "127.0.0.1:50000"},
		{Kind: events.Authenticated, Connection: 1, User: "test", Client: "SSH-2.0-Test_1.0"},
	}
}

// summary describes lines one to a line, with their requests indented.
func summary(lines []Line) string {
	var b strings.Builder
	for _, l := range lines {
		fmt.Fprintf(&b, "%d %s %s", l.ID, l.Kind, l.Outcome)
		for _, kv := range []struct{ k, v string }{{"path", l.Path}, {"reason", l.Reason}, {"read_only", l.ReadOnly}, {"remote", l.Remote}, {"client", l.Client}} {
			if kv.v != "" {
				fmt.Fprintf(&b, " %s=%s", kv.k, kv.v)
			}
		}
		if l.Fault != nil {
			fmt.Fprintf(&b, " fault=%s(%s)", l.Fault.ID, l.Fault.Name)
		}
		if l.Bytes > 0 {
			fmt.Fprintf(&b, " bytes=%d", l.Bytes)
		}
		if l.Duration > 0 {
			fmt.Fprintf(&b, " took=%s", time.Duration(l.Duration))
		}
		if l.InProgress {
			b.WriteString(" in_progress")
		}
		if l.Repeat != nil {
			fmt.Fprintf(&b, " repeat=%d", l.Repeat.ID)
		}
		b.WriteString("\n")
		for _, r := range l.Requests {
			fmt.Fprintf(&b, "  %s %s %s", r.Request, r.Reply, r.Outcome)
			if r.Count > 0 {
				fmt.Fprintf(&b, " count=%d bytes=%d", r.Count, r.Bytes)
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}

func TestLines(t *testing.T) {
	names := map[string]string{"deletes-fail-1": "Deletes fail"}
	tests := []struct {
		name string
		evs  []events.Event
		want string
	}{
		{
			"a session that uploads, lists and logs out",
			append(login(),
				op(1, "SSH_FXP_REALPATH", "/", "SSH_FXP_NAME"),
				open(2, "/in/a.csv", "write"),
				transfer("/in/a.csv", events.Totals{Mode: "write", Writes: 4, BytesWritten: 131072, Closed: "close"}),
				op(3, "SSH_FXP_CLOSE", "/in/a.csv", "SSH_FX_OK"),
				op(4, "SSH_FXP_OPENDIR", "/in", "SSH_FXP_HANDLE"),
				op(5, "SSH_FXP_READDIR", "/in", "SSH_FXP_NAME"),
				op(6, "SSH_FXP_READDIR", "/in", "SSH_FX_EOF"),
				op(7, "SSH_FXP_CLOSE", "/in", "SSH_FX_OK"),
				events.Event{Kind: events.Disconnected, Connection: 1, User: "test"},
			),
			`2 connected ok remote=127.0.0.1:50000 client=SSH-2.0-Test_1.0
4 upload ok path=/in/a.csv bytes=131072 took=1s
  open_write ok ok
  write ok ok count=4 bytes=131072
  close ok ok
7 listing ok path=/in
  opendir ok ok
  readdir ok ok
  readdir eof ok
  close ok ok
11 disconnected ok took=9s
`,
		},
		{
			"a refused delete, named by its fault",
			append(login(),
				fault(1, 1, "SSH_FXP_REMOVE", "/out/r.csv", "deletes-fail-1", "fail"),
				faulted(op(1, "SSH_FXP_REMOVE", "/out/r.csv", "SSH_FX_PERMISSION_DENIED"), "deletes-fail-1"),
				op(2, "SSH_FXP_STAT", "/out/x", "SSH_FX_NO_SUCH_FILE"),
			),
			`2 connected ok remote=127.0.0.1:50000 client=SSH-2.0-Test_1.0
4 delete fault path=/out/r.csv reason=permission_denied fault=deletes-fail-1(Deletes fail)
  remove permission_denied fault
5 check failed path=/out/x reason=no_such_file
  stat no_such_file failed
`,
		},
		{
			"a request whose reply a dropped connection lost",
			append(login(),
				fault(1, 1, "posix-rename@openssh.com", "/a", "drop", "close_connection"),
				events.Event{Kind: events.Disconnected, Connection: 1, User: "test"},
			),
			`2 connected ok remote=127.0.0.1:50000 client=SSH-2.0-Test_1.0
3 rename fault path=/a reason=connection_closed fault=drop(drop)
  rename connection_closed fault
4 disconnected ok took=2s
`,
		},
		{
			"an upload cut off partway, with its fault on a write",
			append(login(),
				open(1, "/in/a.csv", "write"),
				fault(1, 2, "SSH_FXP_WRITE", "/in/a.csv", "cut", "fail"),
				faulted(op(2, "SSH_FXP_WRITE", "/in/a.csv", "SSH_FX_FAILURE"), "cut"),
				events.Event{Kind: events.Transfer, Connection: 1, Path: "/in/a.csv", Rule: "cut", Transfer: &events.Totals{Mode: "write", Writes: 1, BytesWritten: 32768, Closed: "close", Faulted: true}},
				op(3, "SSH_FXP_CLOSE", "/in/a.csv", "SSH_FX_OK"),
			),
			`2 connected ok remote=127.0.0.1:50000 client=SSH-2.0-Test_1.0
3 upload fault path=/in/a.csv reason=failure fault=cut(cut) bytes=32768 took=3s
  open_write ok ok
  write failure fault
  write ok ok count=1 bytes=32768
  close ok ok
`,
		},
		{
			"an upload cut off by a dropped connection, with its write's reply lost",
			append(login(),
				open(1, "/in/a.csv", "write"),
				fault(1, 2, "SSH_FXP_WRITE", "/in/a.csv", "cut", "partial_upload"),
				events.Event{Kind: events.Transfer, Connection: 1, Path: "/in/a.csv", Rule: "cut", Transfer: &events.Totals{Mode: "write", Writes: 1, BytesWritten: 32768, Closed: "session_ended", Faulted: true}},
				events.Event{Kind: events.Disconnected, Connection: 1, User: "test"},
			),
			`2 connected ok remote=127.0.0.1:50000 client=SSH-2.0-Test_1.0
3 upload fault path=/in/a.csv fault=cut(cut) bytes=32768 took=2s
  open_write ok ok
  write ok ok count=1 bytes=32768
  write connection_closed fault
6 disconnected ok took=4s
`,
		},
		{
			"a download its connection's end cut off, and one still going",
			append(login(),
				open(1, "/out/a.csv", "read"),
				transfer("/out/a.csv", events.Totals{Mode: "read", Reads: 2, BytesRead: 65536, Closed: "session_ended"}),
				open(2, "/out/b.csv", "read"),
			),
			`2 connected ok remote=127.0.0.1:50000 client=SSH-2.0-Test_1.0
3 download failed path=/out/a.csv reason=connection_closed bytes=65536 took=1s
  open_read ok ok
  read ok ok count=2 bytes=65536
5 download ok path=/out/b.csv in_progress
  open_read ok ok
`,
		},
		{
			"a file downloaded twice",
			append(login(),
				open(1, "/out/a.csv", "read"),
				transfer("/out/a.csv", events.Totals{Mode: "read", Reads: 1, BytesRead: 10, Closed: "close"}),
				open(2, "/out/a.csv", "read"),
				transfer("/out/a.csv", events.Totals{Mode: "read", Reads: 1, BytesRead: 10, Closed: "close"}),
			),
			`2 connected ok remote=127.0.0.1:50000 client=SSH-2.0-Test_1.0
3 download ok path=/out/a.csv bytes=10 took=1s
  open_read ok ok
  read ok ok count=1 bytes=10
5 download ok path=/out/a.csv bytes=10 took=1s repeat=3
  open_read ok ok
  read ok ok count=1 bytes=10
`,
		},
		{
			"an upload refused at its open by a read-only path",
			append(login(),
				func() events.Event {
					e := op(1, "SSH_FXP_OPEN", "/ref/a.csv", "SSH_FX_PERMISSION_DENIED")
					e.Mode, e.ReadOnly = "write", "/ref"
					return e
				}(),
				op(2, "SSH_FXP_REALPATH", "/nowhere/..", "SSH_FX_NO_SUCH_FILE"),
			),
			`2 connected ok remote=127.0.0.1:50000 client=SSH-2.0-Test_1.0
3 upload failed path=/ref/a.csv reason=permission_denied read_only=/ref
  open_write permission_denied failed
4 realpath failed path=/nowhere/.. reason=no_such_file
  realpath no_such_file failed
`,
		},
		{
			"a connection a fault ended before its login, and an outage",
			[]events.Event{
				{Kind: events.Connected, Connection: 1, Remote: "127.0.0.1:50001"},
				fault(1, 0, "connect", "", "slam", "close_connection"),
				{Kind: events.Disconnected, Connection: 1},
				fault(0, 0, "", "", "outage", "listener_down"),
			},
			`3 connection_failed fault remote=127.0.0.1:50001 fault=slam(slam)
4 outage fault fault=outage(outage)
`,
		},
		{
			"a login that a fault ended",
			append(login(),
				fault(1, 0, "authenticate", "", "logins", "close_connection"),
				events.Event{Kind: events.Disconnected, Connection: 1, User: "test"},
			),
			`2 connected fault remote=127.0.0.1:50000 client=SSH-2.0-Test_1.0 fault=logins(logins)
  authenticate ok fault
4 disconnected ok took=2s
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := summary(Lines(numbered(tt.evs...), names)); got != tt.want {
				t.Errorf("Lines:\n%s\nwant:\n%s", got, tt.want)
			}
		})
	}
}
