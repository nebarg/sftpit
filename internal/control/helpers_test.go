package control_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"log/slog"
	"net/http"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/backend"
	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/control"
	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/runs"
	"github.com/nebarg/sftpit/internal/sshfront"
)

// start starts runs with opts, whose scenarios are chaos, with no seed, and
// own, which pins seed 9, and returns them with their control API.
func start(t *testing.T, opts runs.Options) (*runs.Manager, http.Handler) {
	t.Helper()
	w, err := runs.TempWorkspace()
	if err != nil {
		t.Fatalf("TempWorkspace: %v", err)
	}
	t.Cleanup(func() { w.Close() })
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	opts.Server = sshfront.Config{HostKeys: []ssh.Signer{hostKey}, Users: []sshfront.User{{Name: "test", Password: "test", Home: "/"}}}
	opts.Limits = backend.Limits{MaxFileBytes: 1 << 20, MaxTotalBytes: 1 << 20, MaxFiles: 100, MaxOpenFiles: 10}
	opts.Scenarios = map[string]config.Scenario{"chaos": {}, "own": {Seed: seedOf(9)}}
	opts.Logger = slog.New(slog.DiscardHandler)
	m, err := runs.Start(w, opts)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { m.Close() })
	return m, control.Handler(m)
}

func seedOf(n faults.Seed) *faults.Seed { return &n }

func nameOf(name string) *string { return &name }
