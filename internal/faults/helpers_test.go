package faults_test

import (
	"log/slog"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

const testSeed = faults.Seed(481516)

var (
	failure = sftpproxy.Fail{When: sftpproxy.Before, Status: sftpwire.StatusFailure}
	denied  = sftpproxy.Fail{When: sftpproxy.Before, Status: sftpwire.StatusPermissionDenied}
	cutOff  = sftpproxy.PartialUpload{Cutoff: 1 << 20, Result: failure}
)

var (
	outage = sftpproxy.ListenerDown{Duration: 5 * time.Second, CloseExisting: true}
	// drawnOutage is an outage whose rule draws its duration from
	// someSeconds, as the configuration writes one.
	drawnOutage = sftpproxy.ListenerDown{CloseExisting: true}
	someSeconds = &faults.Range[time.Duration]{Min: time.Second, Max: time.Minute}
)

func openFor(path string, flags uint32) sftpproxy.Request {
	return sftpproxy.Request{Packet: &sftpwire.Open{Path: path, Flags: flags}, Path: path}
}

func on(p sftpwire.Packet, path string) sftpproxy.Request {
	return sftpproxy.Request{Packet: p, Path: path}
}

func newEngine(t *testing.T, rules ...faults.Rule) *faults.Engine {
	t.Helper()
	e, err := faults.New(rules, nil, testSeed, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

// session returns the faults of a session of user, logged in with key, or
// with a password if key is "".
func session(e *faults.Engine, user, key string) func(sftpproxy.Request) sftpproxy.Action {
	return e.Session(faults.Client{User: user, KeyFingerprint: key}).Decide
}

// unreleased returns a without the release that the engine gives a delay,
// stall or freeze, which ends it once its rule is removed, so that it can be
// compared with the rule's own action.
func unreleased(a sftpproxy.Action) sftpproxy.Action {
	switch a := a.(type) {
	case sftpproxy.Delay:
		a.Release = nil
		return a
	case sftpproxy.Stall:
		a.Release = nil
		return a
	case sftpproxy.Freeze:
		a.Release = nil
		return a
	}
	return a
}

func failOn(id string, m faults.Match) faults.Rule {
	return faults.Rule{ID: id, Match: m, Action: failure}
}

func ops(o ...faults.Operation) []faults.Operation { return o }

func at(d time.Duration) *faults.Range[time.Duration] {
	return &faults.Range[time.Duration]{Min: d, Max: d}
}

var stat = faults.Match{Operations: ops(faults.Stat)}
