package main

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestServeWritesAReadyFileWhileItRuns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ready.json")
	// An earlier serve's ready file is replaced.
	writeTestFile(t, path, goneReadyFile("127.0.0.1:2"))

	s := startServe(t, "--ready-file", path)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the ready file: %v", err)
	}
	var ready struct {
		SFTPAddress string `json:"sftp_address"`
		HTTPAddress string `json:"http_address"`
		Workspace   string `json:"workspace"`
		HostKeys    []struct {
			Type        string `json:"type"`
			Fingerprint string `json:"fingerprint"`
		} `json:"host_keys"`
	}
	if err := json.Unmarshal(b, &ready); err != nil {
		t.Fatalf("the ready file holds %s: %v", b, err)
	}
	if ready.SFTPAddress != s.addr || ready.HTTPAddress != s.apiAddr || ready.Workspace != s.workspace {
		t.Errorf("the ready file holds %s, want the addresses and workspace in the banner:\n%s", b, s.stdout.String())
	}
	var listed []string
	for _, key := range ready.HostKeys {
		listed = append(listed, key.Type+" "+key.Fingerprint)
	}
	var banner []string
	for _, m := range hostKeyLine.FindAllStringSubmatch(s.stdout.String(), -1) {
		banner = append(banner, m[1])
	}
	if len(listed) != 2 || !slices.Equal(listed, banner) {
		t.Errorf("the ready file lists the host keys %q, want those in the banner, %q", listed, banner)
	}
	switch info, err := os.Stat(path); {
	case err != nil:
		t.Errorf("the ready file: %v", err)
	case info.Mode().Perm() != 0o644:
		t.Errorf("the ready file has mode %v, want 0644", info.Mode().Perm())
	}
	if got := listNames(t, dir); !slices.Equal(got, []string{"ready.json"}) {
		t.Errorf("the ready file's directory holds %v, want only the ready file", got)
	}

	if code := s.stop(t); code != exitOK {
		t.Fatalf("serve exited with %d\n%s", code, s.stderr.String())
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the ready file outlived serve (%v)", err)
	}
}

// TestServeStopsCleanlyIfTheReadyFileHasGone checks a harness that removes
// the ready file, or its directory, before it stops serve.
func TestServeStopsCleanlyIfTheReadyFileHasGone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ready.json")
	s := startServe(t, "--ready-file", path)
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if code := s.stop(t); code != exitOK || strings.Contains(s.stderr.String(), "ready file") {
		t.Errorf("serve stopped with %d, stderr:\n%s\nwant a clean stop", code, s.stderr.String())
	}
}

func TestServeRemovesAStaleReadyFileEvenIfItCannotStart(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	path := filepath.Join(t.TempDir(), "ready.json")
	writeTestFile(t, path, goneReadyFile("127.0.0.1:2"))

	var stdout, stderr syncBuffer
	if code := run(commandContext(t), []string{"serve", "--sftp-listen", ln.Addr().String(), "--http-listen", "127.0.0.1:0", "--ready-file", path}, &stdout, &stderr); code != exitFailure {
		t.Fatalf("serve on an occupied port exited with %d, want %d\n%s", code, exitFailure, stderr.String())
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the stale ready file is still there (%v), so a harness would take it for this serve's", err)
	}
}

func TestServeRefusesAReadyFileItCannotWrite(t *testing.T) {
	dir := t.TempDir()
	others := map[string]string{
		"sftpit.yaml":  "schema_version: 1\n",
		"empty.json":   "{}",
		"another.json": `{"http_address": "127.0.0.1:8122", "name": "app"}`,
		"partial.json": `{"http_address": "127.0.0.1:8122"}`,
		"notes.json":   goneReadyFile("127.0.0.1:8122") + "\nnotes\n",
	}
	for name, content := range others {
		writeTestFile(t, filepath.Join(dir, name), content)
	}
	readOnly := filepath.Join(dir, "read-only")
	if err := os.Mkdir(readOnly, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(readOnly, 0o700) })
	tests := []struct {
		name, path, want string
	}{
		{"a missing directory", filepath.Join(dir, "missing", "ready.json"), "does not exist"},
		{"a directory it cannot write", filepath.Join(readOnly, "ready.json"), "permission denied"},
		{"another file", filepath.Join(dir, "sftpit.yaml"), "already exists and is not a ready file, so sftpit will not replace it"},
		{"an empty JSON object", filepath.Join(dir, "empty.json"), "already exists and is not a ready file"},
		{"another JSON file", filepath.Join(dir, "another.json"), "already exists and is not a ready file"},
		{"part of a ready file", filepath.Join(dir, "partial.json"), "already exists and is not a ready file"},
		{"a ready file with more after it", filepath.Join(dir, "notes.json"), "already exists and is not a ready file"},
		{"a directory", dir, "already exists and is not a ready file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if filepath.Dir(tt.path) == readOnly && os.Geteuid() == 0 {
				t.Skip("root can write in any directory")
			}
			// A serve that took the file would run until the deadline.
			ctx, cancel := context.WithTimeout(t.Context(), startTimeout)
			defer cancel()
			var stdout, stderr syncBuffer
			code := run(ctx, []string{"serve", "--sftp-listen", "127.0.0.1:0", "--http-listen", "127.0.0.1:0", "--ready-file", tt.path}, &stdout, &stderr)
			if code != exitUsage || !strings.Contains(stderr.String(), "--ready-file: ") || !strings.Contains(stderr.String(), tt.want) {
				t.Errorf("exit %d, stderr %q, want %d and %q", code, stderr.String(), exitUsage, tt.want)
			}
		})
	}
	for name, content := range others {
		if b, err := os.ReadFile(filepath.Join(dir, name)); err != nil || string(b) != content {
			t.Errorf("%s holds %q (%v), want it untouched", name, b, err)
		}
	}
}

func TestWriteReadyFileLeavesNothingBehindWhenItFails(t *testing.T) {
	dir := t.TempDir()
	taken := filepath.Join(dir, "ready.json")
	if err := os.Mkdir(taken, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeReadyFile(taken, readyFile{HTTPAddress: "127.0.0.1:8122"}); err == nil {
		t.Fatal("writeReadyFile over a directory succeeded")
	}
	if got := listNames(t, dir); !slices.Equal(got, []string{"ready.json"}) {
		t.Errorf("the directory holds %v after the failed write, want only what was there", got)
	}
}

var hostKeyLine = regexp.MustCompile(`(?m)^    (\S+ SHA256:\S+)$`)

func listNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}
