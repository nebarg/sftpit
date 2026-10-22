package integration

import (
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
)

// TestOpenSSHConnectionEvents acts on OpenSSH's connection as the server
// accepts it and as the server accepts its login, and checks what the
// client reports.
func TestOpenSSHConnectionEvents(t *testing.T) {
	sftpPath := openSSHOrSkip(t)

	signer, err := ssh.NewSignerFromKey(clientKey)
	if err != nil {
		t.Fatalf("client signer: %v", err)
	}
	connect := faults.Match{Operations: []faults.Operation{faults.Connect}}
	login := faults.Match{Operations: []faults.Operation{faults.Authenticate}, User: testUser, KeyFingerprint: ssh.FingerprintSHA256(signer.PublicKey())}
	tests := []struct {
		name    string
		match   faults.Match
		action  sftpproxy.Action
		options []string
		// output holds the forms in which the tested versions of sftp
		// report the fault.
		output []string
		// log is how the fault is logged, after its connection and event.
		log string
	}{
		{
			name:    "a slow connect",
			match:   connect,
			action:  sftpproxy.Delay{Duration: 3 * time.Second},
			options: []string{"ConnectTimeout=1"},
			output:  []string{"Connection timed out during banner exchange"},
			log:     "fault=delay duration=3s",
		},
		{
			name:   "a close at connect",
			match:  connect,
			action: sftpproxy.Drop{},
			output: []string{"kex_exchange_identification: Connection closed by remote host", "Connection closed by 127.0.0.1 port"},
			log:    "fault=close_connection mode=fin",
		},
		{
			name:   "a reset at connect",
			match:  connect,
			action: sftpproxy.Drop{Reset: true},
			// The client reports a reset as its write of its version or
			// its read of the server's fails, whichever comes first, and
			// on Linux may name no peer, as the reset leaves none.
			output: []string{"Connection reset by", "banner exchange: Connection to 127.0.0.1 port"},
			log:    "fault=close_connection mode=rst",
		},
		{
			name:    "a freeze at connect",
			match:   connect,
			action:  sftpproxy.Freeze{Limit: 5 * time.Second},
			options: []string{"ConnectTimeout=1"},
			output:  []string{"Connection timed out during banner exchange"},
			log:     "fault=freeze_connection limit=5s",
		},
		{
			name:   "a close at login",
			match:  login,
			action: sftpproxy.Drop{},
			output: []string{"Connection closed by 127.0.0.1 port"},
			log:    "user=test fault=close_connection mode=fin",
		},
		{
			name:   "a reset at login",
			match:  login,
			action: sftpproxy.Drop{Reset: true},
			output: []string{"Connection reset by 127.0.0.1 port"},
			log:    "user=test fault=close_connection mode=rst",
		},
		{
			name:   "a freeze at login",
			match:  login,
			action: sftpproxy.Freeze{Limit: time.Second},
			output: []string{"Connection closed by 127.0.0.1 port"},
			log:    "user=test fault=freeze_connection limit=1s",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs snapshotLog
			rules, err := faults.New([]faults.Rule{{ID: "event", Match: tt.match, Action: tt.action}}, 0, logs.logger())
			if err != nil {
				t.Fatalf("faults.New: %v", err)
			}
			srv := startServerWithRules(t, rules, sftpproxy.Options{Logger: logs.logger()})

			out, err := openSSH(t, sftpPath, srv, t.TempDir(), "ls\n", tt.options...)
			if err == nil {
				t.Errorf("sftp succeeded, want the fault to end it:\n%s", out)
			}
			if !slices.ContainsFunc(tt.output, func(o string) bool { return strings.Contains(string(out), o) }) {
				t.Errorf("sftp output contains none of %q:\n%s", tt.output, out)
			}
			if got := rules.Counts()["event"]; got != (faults.Counts{Matched: 1, Selected: 1, Fired: 1}) {
				t.Errorf("counts = %+v, want the one connection's event selected and fired", got)
			}
			event := tt.match.Operations[0]
			if want := `msg="injected fault" conn=1 request=` + string(event) + " " + tt.log; !strings.Contains(logs.text(), want) {
				t.Errorf("logs lack %q:\n%s", want, logs.text())
			}
		})
	}
}

// TestOpenSSHWaitsForASlowLogin delays OpenSSH's login, which then goes on
// as usual.
func TestOpenSSHWaitsForASlowLogin(t *testing.T) {
	sftpPath := openSSHOrSkip(t)

	var logs snapshotLog
	rules, err := faults.New([]faults.Rule{{
		ID:     "slow-login",
		Match:  faults.Match{Operations: []faults.Operation{faults.Authenticate}},
		Action: sftpproxy.Delay{Duration: time.Second},
	}}, 0, logs.logger())
	if err != nil {
		t.Fatalf("faults.New: %v", err)
	}
	srv := startServerWithRules(t, rules, sftpproxy.Options{Logger: logs.logger()})

	start := time.Now()
	out, err := openSSH(t, sftpPath, srv, t.TempDir(), "ls\n")
	if err != nil {
		t.Fatalf("sftp failed: %v\n%s", err, out)
	}
	if took := time.Since(start); took < time.Second {
		t.Errorf("sftp took %v, want at least the second its login was delayed", took)
	}
	if want := `msg="injected fault" conn=1 request=authenticate user=test fault=delay duration=1s`; !strings.Contains(logs.text(), want) {
		t.Errorf("logs lack %q:\n%s", want, logs.text())
	}
}
