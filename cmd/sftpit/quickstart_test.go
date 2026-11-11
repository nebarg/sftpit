package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkg/sftp"

	"github.com/nebarg/sftpit/internal/testutil"
)

// TestTheQuickstartExample takes the README's quickstart steps against
// examples/quickstart, with pkg/sftp's client in place of OpenSSH's sftp:
// an upload that tries again passes, and one that publishes the cut-off
// upload fails on the published file's hash.
func TestTheQuickstartExample(t *testing.T) {
	t.Parallel()
	orders, err := os.ReadFile(filepath.Join("..", "..", "examples", "quickstart", "orders.csv"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		retry      bool
		code       int
		hashReport string
	}{
		{"uploading again passes", true, exitOK, "  pass  file_hash /incoming/orders.csv"},
		{"publishing the cut-off upload fails", false, exitAssertionsFailed, "  FAIL  file_hash /incoming/orders.csv"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ready := filepath.Join(t.TempDir(), "ready.json")
			s := startServe(t, "--config", filepath.Join("..", "..", "examples", "quickstart", "sftpit.yaml"), "--scenario", "upload-recovery", "--ready-file", ready)
			c := s.dial(t, "test", "test")
			if err := c.Mkdir("/incoming"); err != nil {
				t.Fatalf("Mkdir: %v", err)
			}
			if err := put(c, orders); err == nil {
				t.Fatal("the first upload succeeded, want it cut off")
			}
			if tt.retry {
				if err := put(c, orders); err != nil {
					t.Fatalf("the second upload: %v", err)
				}
			}
			if err := c.Rename("/incoming/orders.csv.part", "/incoming/orders.csv"); err != nil {
				t.Fatalf("Rename: %v", err)
			}

			var stdout, stderr testutil.SyncBuffer
			code := run(commandContext(t), []string{"assert", "--ready-file", ready}, &stdout, &stderr)
			if code != tt.code || !strings.Contains(stdout.String(), tt.hashReport) {
				t.Errorf("assert: exit %d, want %d and %q:\n%s%s", code, tt.code, tt.hashReport, stdout.String(), stderr.String())
			}
		})
	}
}

// put uploads data to /incoming/orders.csv.part, as sftp's put does.
func put(c *sftp.Client, data []byte) error {
	f, err := c.Create("/incoming/orders.csv.part")
	if err != nil {
		return err
	}
	_, err = f.ReadFrom(bytes.NewReader(data))
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}
