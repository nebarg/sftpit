package main

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// TestTheQuickstartExample takes the README's quickstart steps, with
// pkg/sftp's client in place of OpenSSH's sftp: with "Deletes fail" on for
// /outgoing, deleting the example's report is refused, and once the fault
// is off, the delete succeeds.
func TestTheQuickstartExample(t *testing.T) {
	t.Parallel()
	s := startServe(t, "--seed-dir", filepath.Join("..", "..", "examples", "quickstart", "seed"))
	api := "http://" + s.apiAddr + "/api"
	requestJSONStatus(t, "POST", api+"/faults", `{"preset": "deletes_fail", "folder": "/outgoing"}`, http.StatusCreated)

	c := s.dial(t, "test", "test")
	if err := c.Remove("/outgoing/report.csv"); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("a delete with the fault on = %v, want it refused", err)
	}
	if got := requestJSON(t, api+"/faults/deletes-fail-1"); got["happened"] != 1.0 {
		t.Errorf("the fault = %v, want it to have happened once", got)
	}

	requestJSONStatus(t, "PATCH", api+"/faults/deletes-fail-1", `{"on": false}`, http.StatusOK)
	if err := c.Remove("/outgoing/report.csv"); err != nil {
		t.Errorf("a delete with the fault off = %v, want it to succeed", err)
	}
}
