package control_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/backend"
	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/control"
	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/runs"
	"github.com/nebarg/sftpit/internal/sshfront"
)

// testScenarios are the scenarios that start configures: chaos, with no
// seed, and own, which pins seed 9.
var testScenarios = map[string]config.Scenario{"chaos": {}, "own": {Seed: new(faults.Seed(9))}}

var testUsers = []sshfront.User{{Name: "test", Password: "test", Home: "/"}}

// start starts runs with opts, whose scenarios are testScenarios, and
// returns them with their control API.
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
	opts.Server = sshfront.Config{HostKeys: []ssh.Signer{hostKey}, Users: testUsers}
	opts.Limits = backend.Limits{MaxFileBytes: 1 << 20, MaxTotalBytes: 1 << 20, MaxFiles: 100, MaxOpenFiles: 10}
	opts.Scenarios = testScenarios
	opts.Logger = slog.New(slog.DiscardHandler)
	m, err := runs.Start(w, opts)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { m.Close() })
	return m, control.Handler(m, control.Options{})
}

const denyStats = `{"id": "deny-stats", "match": {"operation": "stat", "user": "test"}, "action": {"type": "fail", "when": "before", "status": "permission_denied"}}`

const host = "127.0.0.1:8122"

// call makes a request to api as the command line would, and returns the
// status code and decoded body.
func call(t *testing.T, api http.Handler, method, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = host
	if method != "GET" {
		req.Header.Set(control.RequestHeader, "1")
	}
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("%s %s has Content-Type %q", method, path, ct)
	}
	var decoded map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("%s %s = %d %q: %v", method, path, rec.Code, rec.Body, err)
	}
	return rec.Code, decoded
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// equalJSON reports whether two decoded JSON values are equal.
func equalJSON(a, b any) bool {
	x, errX := json.Marshal(a)
	y, errY := json.Marshal(b)
	return errX == nil && errY == nil && string(x) == string(y)
}
