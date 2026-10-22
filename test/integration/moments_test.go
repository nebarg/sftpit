package integration

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
)

// TestOpenSSHMoments acts on OpenSSH's connection at a moment in the middle
// of an upload, whatever the client is doing then, and checks what the
// client reports and what the upload leaves behind.
func TestOpenSSHMoments(t *testing.T) {
	sftpPath := openSSHOrSkip(t)

	// Each write waits, so that the upload lasts longer than the moment.
	slow := faults.Rule{ID: "slow", Priority: 1, Match: faults.Match{Operations: []faults.Operation{faults.Write}}, Action: sftpproxy.Delay{When: sftpproxy.Before, Duration: 20 * time.Millisecond}}
	moment := &faults.Range[time.Duration]{Min: 500 * time.Millisecond, Max: 500 * time.Millisecond}
	tests := []struct {
		name string
		rule faults.Rule
		// output holds the forms in which the tested versions of sftp
		// report the moment.
		output []string
	}{
		{
			name:   "reset into the upload",
			rule:   faults.Rule{ID: "moment", Match: faults.Match{Operations: []faults.Operation{faults.Write}}, Trigger: &faults.Trigger{Anchor: faults.Transfer, At: moment}, Action: sftpproxy.Drop{Reset: true}},
			output: []string{"Read from remote host 127.0.0.1: Connection reset by peer", "client_loop: send disconnect: Broken pipe"},
		},
		{
			name:   "close the connection",
			rule:   faults.Rule{ID: "moment", Trigger: &faults.Trigger{Anchor: faults.Connection, At: moment}, Action: sftpproxy.Drop{}},
			output: []string{"Connection to 127.0.0.1 closed by remote host."},
		},
		{
			name:   "freeze the connection",
			rule:   faults.Rule{ID: "moment", Trigger: &faults.Trigger{Anchor: faults.Connection, At: moment}, Action: sftpproxy.Freeze{Limit: 5 * time.Second}},
			output: []string{"Timeout, server 127.0.0.1 not responding."},
		},
		// sftp ends when its session does, although the connection is
		// still open.
		{
			name:   "close the session",
			rule:   faults.Rule{ID: "moment", Trigger: &faults.Trigger{Anchor: faults.Connection, At: moment}, Action: sftpproxy.EndSession{}},
			output: []string{"Connection closed"},
		},
	}
	data := randomBytes(2 << 20)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs snapshotLog
			rules, err := faults.New([]faults.Rule{slow, tt.rule}, 0, logs.logger())
			if err != nil {
				t.Fatalf("faults.New: %v", err)
			}
			srv := startServerWithRules(t, rules, sftpproxy.Options{Logger: logs.logger()})
			work := t.TempDir()
			writeFile(t, filepath.Join(work, "orders.csv"), data)

			// The keepalives let the client notice a frozen connection.
			out, err := openSSH(t, sftpPath, srv, work, "put orders.csv\n", "ServerAliveInterval=1", "ServerAliveCountMax=2")
			srv.waitForSessions()
			if err == nil {
				t.Errorf("sftp succeeded, want the moment to end it:\n%s", out)
			}
			if !slices.ContainsFunc(tt.output, func(o string) bool { return strings.Contains(string(out), o) }) {
				t.Errorf("sftp output contains none of %q:\n%s", tt.output, out)
			}
			stored, err := os.ReadFile(filepath.Join(srv.files, "orders.csv"))
			if err != nil || len(stored) == 0 || len(stored) >= len(data) || string(stored) != string(data[:len(stored)]) {
				t.Errorf("the upload stored %d bytes (%v), want a start of its %d from before the moment", len(stored), err, len(data))
			}
			if got := rules.Counts()["moment"].Fired; got != 1 {
				t.Errorf("the moment fired %d times, want once", got)
			}
			if !strings.Contains(logs.text(), `msg="rule fired" rule=moment`) || !strings.Contains(logs.text(), "closed_by=fault") {
				t.Errorf("logs lack the moment's firing or the upload's snapshot:\n%s", logs.text())
			}
		})
	}
}

// TestEachOpenSSHConnectionHasItsOwnMoment closes each of two connections
// from OpenSSH at a moment measured from when it logged in.
func TestEachOpenSSHConnectionHasItsOwnMoment(t *testing.T) {
	sftpPath := openSSHOrSkip(t)

	rules, err := faults.New([]faults.Rule{
		{ID: "slow", Match: faults.Match{Operations: []faults.Operation{faults.Write}}, Action: sftpproxy.Delay{When: sftpproxy.Before, Duration: 20 * time.Millisecond}},
		{ID: "moment", Trigger: &faults.Trigger{Anchor: faults.Connection, At: &faults.Range[time.Duration]{Min: 300 * time.Millisecond, Max: 300 * time.Millisecond}}, Action: sftpproxy.Drop{}},
	}, 0, nil)
	if err != nil {
		t.Fatalf("faults.New: %v", err)
	}
	srv := startServerWithRules(t, rules, sftpproxy.Options{})
	work := t.TempDir()
	writeFile(t, filepath.Join(work, "orders.csv"), randomBytes(1<<20))
	for i := range 2 {
		out, err := openSSH(t, sftpPath, srv, work, "put orders.csv\n")
		if err == nil || !strings.Contains(string(out), "Connection to 127.0.0.1 closed by remote host.") {
			t.Errorf("connection %d: sftp = %v, want its connection closed:\n%s", i+1, err, out)
		}
	}
	srv.waitForSessions()
	if got := rules.Counts()["moment"]; got != (faults.Counts{Matched: 2, Selected: 2, Fired: 2}) {
		t.Errorf("counts = %+v, want each connection's moment fired", got)
	}
}
