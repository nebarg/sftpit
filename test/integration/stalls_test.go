package integration

import (
	"strings"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
)

// TestOpenSSHUntilAStallIsReleased stalls OpenSSH's listing and releases it
// after its keepalives would have given up on a frozen connection, about
// 2.6 s, and releases a frozen connection before they do.
func TestOpenSSHUntilAStallIsReleased(t *testing.T) {
	t.Parallel()
	sftpPath := openSSHOrSkip(t)
	// Only the listing's first request, its OPENDIR, since its READDIRs
	// would otherwise each stall in turn.
	list := faults.Match{Operations: []faults.Operation{faults.List}, Occurrence: []uint64{1}}
	tests := []struct {
		name   string
		action sftpproxy.Action
		hold   time.Duration
		// output is what sftp reports, which it does with success only for
		// a stall.
		output string
		ok     bool
	}{
		// The SSH layer keeps answering keepalives, so only an operation
		// timeout could end a stall.
		{"stall", sftpproxy.Stall{When: sftpproxy.Before, Limit: time.Minute}, 4 * time.Second, "orders.csv", true},
		{"freeze", sftpproxy.Freeze{When: sftpproxy.Before, Limit: time.Minute}, 500 * time.Millisecond, "Connection to 127.0.0.1 closed by remote host.", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs capturedLog
			srv := startScenario(t, []faults.Rule{{ID: "held", Match: list, Action: tt.action}}, 0, logs.logger())
			writeFile(t, srv.path("/orders.csv"), []byte("id,total\n"))
			released := make(chan time.Time, 1)
			go func() {
				deadline := time.Now().Add(10 * time.Second)
				for srv.counts(t, "held").Fired == 0 && time.Now().Before(deadline) {
					time.Sleep(10 * time.Millisecond)
				}
				time.Sleep(tt.hold)
				srv.releaseStalls(t)
				released <- time.Now()
			}()

			out, err := openSSH(t, sftpPath, srv, t.TempDir(), "ls\n", "ServerAliveInterval=1", "ServerAliveCountMax=2")
			ended := time.Now()
			srv.waitForSessions()
			at := <-released
			if (err == nil) != tt.ok || !strings.Contains(string(out), tt.output) {
				t.Errorf("sftp = %v with output\n%s\nwant success %v and %q", err, out, tt.ok, tt.output)
			}
			if !strings.Contains(logs.text(), `msg="fault released"`) {
				t.Errorf("logs lack the release:\n%s", logs.text())
			}
			if d := ended.Sub(at); d < 0 || d > 2*time.Second {
				t.Errorf("sftp ended %v after the release, want soon after it", d)
			}
		})
	}
}
