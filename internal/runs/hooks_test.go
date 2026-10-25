package runs

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sshfront"
)

func TestFaultsAtConnectEndWithTheHandshake(t *testing.T) {
	tests := []struct {
		name   string
		action sftpproxy.Action
	}{
		{"delay", sftpproxy.Delay{Duration: time.Minute}},
		{"freeze", sftpproxy.Freeze{Limit: time.Minute}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, addr := startManager(t, Options{
				Server:    sshfront.Config{HandshakeTimeout: 300 * time.Millisecond},
				Scenarios: map[string]config.Scenario{"connect": {Rules: []faults.Rule{connectRule(tt.action)}}},
				Scenario:  "connect",
			})
			raw, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer raw.Close()
			if err := raw.SetDeadline(time.Now().Add(waitTimeout)); err != nil {
				t.Fatalf("SetDeadline: %v", err)
			}
			if _, err := io.ReadAll(raw); err != nil {
				t.Errorf("the connection was not closed at the handshake timeout: %v", err)
			}
		})
	}
}

func TestShutdownDuringAFreezeIsNoFailure(t *testing.T) {
	logs := make(messages, 64)
	m, addr := startManager(t, Options{
		Scenarios: map[string]config.Scenario{"connect": {Rules: []faults.Rule{connectRule(sftpproxy.Freeze{Limit: time.Minute})}}},
		Scenario:  "connect",
		Logger:    slog.New(logs),
	})
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer raw.Close()
	for receive(t, logs) != "injected fault" {
	}

	closed := make(chan error, 1)
	go func() { closed <- m.Close() }()
	if err := receive(t, closed); err != nil {
		t.Errorf("Close: %v", err)
	}
	for len(logs) > 0 {
		if msg := <-logs; msg == "injecting a fault failed" {
			t.Errorf("closing the frozen connection at shutdown was logged as a failure")
		}
	}
}

// TestArmTimersStartsNoOutageOnceStopped stops a run's timer as it fires,
// many times over, since only a stop that races a firing timer can fall
// between its firing and the outage.
func TestArmTimersStartsNoOutageOnceStopped(t *testing.T) {
	srv, err := sshfront.New(sshfront.Config{
		HostKeys: []ssh.Signer{newHostKey(t)},
		Users:    []sshfront.User{{Name: "test", Password: "test"}},
		Handler:  func(context.Context, *sshfront.Conn, io.ReadWriteCloser) error { return nil },
	})
	if err != nil {
		t.Fatalf("sshfront.New: %v", err)
	}
	defer srv.Close()
	logger := slog.New(slog.DiscardHandler)
	moment := &faults.Range[time.Duration]{Min: time.Millisecond, Max: time.Millisecond}
	outage := faults.Rule{ID: "outage", Trigger: &faults.Trigger{Anchor: faults.Run, At: moment}, Action: sftpproxy.ListenerDown{Duration: time.Minute}}
	for attempt := range 300 {
		rules, err := faults.New([]faults.Rule{outage}, nil, 0, logger)
		if err != nil {
			t.Fatalf("faults.New: %v", err)
		}
		stop := ArmTimers(rules, srv, logger)
		time.Sleep(time.Until(rules.Timers()[0].At))
		stop()
		fired := rules.Counts()["outage"].Fired
		time.Sleep(time.Millisecond)
		if rules.Counts()["outage"].Fired != fired {
			t.Fatalf("attempt %d: the outage fired after stop returned", attempt)
		}
	}
}
