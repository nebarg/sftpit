//go:build unix

package backend_test

import (
	"log/slog"
	"os"
	"testing"

	"github.com/nebarg/sftpit/internal/backend"
)

// TestWritesToARemovedFileDoNotCount checks that writes through a handle
// whose file another session has removed take nothing from the limits: the
// file is no longer in the tree, and goes once the handle closes.
func TestWritesToARemovedFileDoNotCount(t *testing.T) {
	limits := backend.Limits{MaxFileBytes: 10, MaxTotalBytes: 10, MaxFiles: 4, MaxOpenFiles: 4}
	e := newBackendIn(t, t.TempDir(), backend.Options{Limits: limits, Logger: slog.New(slog.DiscardHandler)})
	writer, remover := newClient(t, e, "/"), newClient(t, e, "/")

	f, err := writer.Create("/a")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := remover.Remove("/a"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := f.Write([]byte("01234567")); err != nil {
		t.Fatalf("Write through the removed file's handle: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := writeAt(writer, "/b", "0123456789", 0, os.O_CREATE); err != nil {
		t.Errorf("a write of max_total_bytes once the removed file closed: %v", err)
	}
}
