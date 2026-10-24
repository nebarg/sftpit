package main

import (
	"context"
	"net"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestResetStartsTheNextRun(t *testing.T) {
	ready := serveWithScenarios(t)
	tests := []struct {
		args []string
		want string
	}{
		{nil, `scenario chaos, seed 7 \(pinned\)`},
		{[]string{"--scenario", "own"}, `scenario own, seed 9 \(pinned\)`},
		{[]string{"--seed", "18446744073709551615"}, `scenario own, seed 18446744073709551615 \(pinned\)`},
		{[]string{"--scenario", ""}, `no faults`},
		{[]string{"--scenario", "chaos"}, `scenario chaos, seed \d+ \(fresh\)`},
	}
	var last string
	for _, tt := range tests {
		var stdout, stderr syncBuffer
		code := run(context.Background(), append([]string{"reset", "--ready-file", ready}, tt.args...), &stdout, &stderr)
		m := regexp.MustCompile(`^run (\S+): (` + tt.want + `)\n$`).FindStringSubmatch(stdout.String())
		if code != exitOK || m == nil || m[1] == last {
			t.Fatalf("reset %q: exit %d, stdout %q, stderr %q, want a new run with %s", tt.args, code, stdout.String(), stderr.String(), tt.want)
		}
		last = m[1]
	}
}

func TestResetFailsClearly(t *testing.T) {
	ready := serveWithScenarios(t)
	dir := t.TempDir()
	notReady := filepath.Join(dir, "notes.txt")
	writeTestFile(t, notReady, "notes")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gone := filepath.Join(dir, "gone.json")
	writeTestFile(t, gone, `{"sftp_address": "127.0.0.1:1", "http_address": "`+ln.Addr().String()+`", "workspace": "/gone", "host_keys": []}`)
	ln.Close()

	tests := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"no ready file", nil, exitUsage, "--ready-file is required"},
		{"a negative seed", []string{"--ready-file", ready, "--seed", "-1"}, exitUsage, "a seed is a whole number from 0 to 18446744073709551615"},
		{"a stray argument", []string{"--ready-file", ready, "now"}, exitUsage, `unexpected arguments ["now"]`},
		{"an unknown flag", []string{"--run", "x"}, exitUsage, "flag provided but not defined: -run"},
		{"an unknown scenario", []string{"--ready-file", ready, "--scenario", "flaky"}, exitUsage, `unknown scenario "flaky"; the configuration defines chaos, own`},
		{"a seed without a scenario", []string{"--ready-file", ready, "--scenario", "", "--seed", "7"}, exitUsage, "a seed needs a scenario"},
		{"a missing ready file", []string{"--ready-file", filepath.Join(dir, "missing.json")}, exitFailure, "missing.json"},
		{"another file", []string{"--ready-file", notReady}, exitFailure, "notes.txt is not a ready file that sftpit serve wrote"},
		{"a server that has gone", []string{"--ready-file", gone}, exitFailure, "connection refused"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr syncBuffer
			code := run(context.Background(), append([]string{"reset"}, tt.args...), &stdout, &stderr)
			if code != tt.code || !strings.HasPrefix(stderr.String(), "sftpit reset: ") || !strings.Contains(stderr.String(), tt.want) {
				t.Errorf("exit %d, stderr %q, want %d and %q", code, stderr.String(), tt.code, tt.want)
			}
		})
	}
}

func TestResetHelp(t *testing.T) {
	var stdout, stderr syncBuffer
	if code := run(context.Background(), []string{"reset", "--help"}, &stdout, &stderr); code != exitOK || !strings.Contains(stdout.String(), "Usage: sftpit reset") {
		t.Errorf("exit %d, stdout %q, want the reset usage", code, stdout.String())
	}
}

// serveWithScenarios serves the scenarios chaos, with no seed of its own,
// and own, which pins seed 9, and starts with chaos and seed 7. It returns
// the ready file.
func serveWithScenarios(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	config := filepath.Join(dir, "sftpit.yaml")
	writeTestFile(t, config, "schema_version: 1\nscenarios:\n  chaos: {faults: []}\n  own: {seed: 9, faults: []}\n")
	ready := filepath.Join(dir, "ready.json")
	startServe(t, "--config", config, "--sftp-listen", "127.0.0.1:0", "--scenario", "chaos", "--seed", "7", "--ready-file", ready)
	return ready
}
