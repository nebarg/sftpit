package integration

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/faults"
)

// TestOpenSSHConnectionEvents acts on OpenSSH's connection as the server
// accepts it and as the server accepts its login, and checks what the
// client reports.
func TestOpenSSHConnectionEvents(t *testing.T) {
	t.Parallel()
	sftpPath := openSSHOrSkip(t)

	tests := []struct {
		name    string
		fault   config.Fault
		options []string
		// output holds the forms in which the tested versions of sftp
		// report the fault.
		output []string
		// log is how the fault is logged, after its connection and event.
		log string
	}{
		{
			name:    "a slow connect",
			fault:   config.Fault{Name: "Event", Steps: []string{"connect"}, Do: "wait", Seconds: new(3.0)},
			options: []string{"ConnectTimeout=1"},
			output:  []string{"Connection timed out during banner exchange"},
			log:     "fault=delay duration=3s",
		},
		{
			name:   "a close at connect",
			fault:  config.Fault{Name: "Event", Steps: []string{"connect"}, Do: "drop"},
			output: []string{"kex_exchange_identification: Connection closed by remote host", "Connection closed by 127.0.0.1 port"},
			log:    "fault=close_connection mode=fin",
		},
		{
			name:  "a reset at connect",
			fault: config.Fault{Name: "Event", Steps: []string{"connect"}, Do: "drop", Abrupt: true},
			// The client reports a reset as its write of its version or
			// its read of the server's fails, whichever comes first, and
			// on Linux may name no peer, as the reset leaves none.
			output: []string{"Connection reset by", "banner exchange: Connection to 127.0.0.1 port"},
			log:    "fault=close_connection mode=rst",
		},
		{
			name:    "a freeze at connect",
			fault:   config.Fault{Name: "Event", Steps: []string{"connect"}, Do: "freeze", Seconds: new(5.0)},
			options: []string{"ConnectTimeout=1"},
			output:  []string{"Connection timed out during banner exchange"},
			log:     "fault=freeze_connection limit=5s",
		},
		{
			name:   "a close at login",
			fault:  config.Fault{Name: "Event", Steps: []string{"authenticate"}, Do: "drop", User: testUser},
			output: []string{"Connection closed by 127.0.0.1 port"},
			log:    "user=test fault=close_connection mode=fin",
		},
		{
			name:   "a reset at login",
			fault:  config.Fault{Name: "Event", Steps: []string{"authenticate"}, Do: "drop", Abrupt: true, User: testUser},
			output: []string{"Connection reset by 127.0.0.1 port"},
			log:    "user=test fault=close_connection mode=rst",
		},
		{
			name:   "a freeze at login",
			fault:  config.Fault{Name: "Event", Steps: []string{"authenticate"}, Do: "freeze", Seconds: new(1.0), User: testUser},
			output: []string{"Connection closed by 127.0.0.1 port"},
			log:    "user=test fault=freeze_connection limit=1s",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var logs capturedLog
			srv := startFaults(t, logs.logger(), tt.fault)

			out, err := openSSH(t, sftpPath, srv, t.TempDir(), "ls\n", tt.options...)
			if err == nil {
				t.Errorf("sftp succeeded, want the fault to end it:\n%s", out)
			}
			if !slices.ContainsFunc(tt.output, func(o string) bool { return strings.Contains(string(out), o) }) {
				t.Errorf("sftp output contains none of %q:\n%s", tt.output, out)
			}
			if got := srv.counts("event-1"); got != (faults.Counts{Matched: 1, Selected: 1, Fired: 1}) {
				t.Errorf("counts = %+v, want the one connection's event selected and fired", got)
			}
			if want := `msg="injected fault" conn=1 operation=` + tt.fault.Steps[0] + " " + tt.log; !strings.Contains(logs.text(), want) {
				t.Errorf("logs lack %q:\n%s", want, logs.text())
			}
		})
	}
}

// TestOpenSSHWaitsForASlowLogin delays OpenSSH's login, which then goes on
// as usual.
func TestOpenSSHWaitsForASlowLogin(t *testing.T) {
	t.Parallel()
	sftpPath := openSSHOrSkip(t)

	var logs capturedLog
	srv := startFaults(t, logs.logger(), config.Fault{Steps: []string{"authenticate"}, Do: "wait", Seconds: new(1.0)})

	start := time.Now()
	out, err := openSSH(t, sftpPath, srv, t.TempDir(), "ls\n")
	if err != nil {
		t.Fatalf("sftp failed: %v\n%s", err, out)
	}
	if took := time.Since(start); took < time.Second {
		t.Errorf("sftp took %v, want at least the second its login was delayed", took)
	}
	if want := `msg="injected fault" conn=1 operation=authenticate user=test fault=delay duration=1s`; !strings.Contains(logs.text(), want) {
		t.Errorf("logs lack %q:\n%s", want, logs.text())
	}
}
