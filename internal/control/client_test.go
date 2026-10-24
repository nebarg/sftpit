package control_test

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/control"
	"github.com/nebarg/sftpit/internal/runs"
)

func TestClientResets(t *testing.T) {
	m, api := start(t, runs.Options{Scenario: "chaos", Seed: seedOf(7)})
	srv := httptest.NewServer(api)
	defer srv.Close()
	c := &control.Client{Addr: srv.Listener.Addr().String()}

	status, err := c.Reset(t.Context(), control.ResetRequest{Scenario: nameOf("own")})
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if run := status.Run; run.ID != m.Status().Run.ID || run.Scenario != "own" || run.Seed != 9 || !run.SeedPinned || status.SFTP.State != runs.StateUp {
		t.Errorf("Reset = %+v, want the next run, of own with seed 9", status)
	}
	seed := control.Seed(8)
	if status, err := c.Reset(t.Context(), control.ResetRequest{Run: status.Run.ID, Seed: &seed}); err != nil || status.Run.Seed != 8 {
		t.Errorf("Reset of the current run with seed 8 = %+v, %v", status, err)
	}

	tests := []struct {
		req  control.ResetRequest
		code int
		want string
	}{
		{control.ResetRequest{Scenario: nameOf("flaky")}, http.StatusBadRequest, `unknown scenario "flaky"`},
		{control.ResetRequest{Run: "20260101-000000.000-0000"}, http.StatusConflict, "the current run is "},
	}
	for _, tt := range tests {
		var refused *control.Error
		if _, err := c.Reset(t.Context(), tt.req); !errors.As(err, &refused) || refused.StatusCode != tt.code || !strings.Contains(refused.Message, tt.want) || err.Error() != refused.Message {
			t.Errorf("Reset(%+v) = %v, want a %d saying %q", tt.req, err, tt.code, tt.want)
		}
	}
}

func TestClientReportsAServerItCannotUse(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    string
		code    int
	}{
		{"an error without JSON", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "upstream gone", http.StatusBadGateway)
		}, "502 Bad Gateway", http.StatusBadGateway},
		{"a reply that is not JSON", func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("<html>"))
		}, "control: read the reply to POST /api/v1/reset: ", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()
			_, err := (&control.Client{Addr: srv.Listener.Addr().String()}).Reset(t.Context(), control.ResetRequest{})
			var refused *control.Error
			if err == nil || !strings.Contains(err.Error(), tt.want) || errors.As(err, &refused) != (tt.code != 0) || (tt.code != 0 && refused.StatusCode != tt.code) {
				t.Errorf("Reset = %v, want %q", err, tt.want)
			}
		})
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	_, err = (&control.Client{Addr: ln.Addr().String()}).Reset(t.Context(), control.ResetRequest{})
	var refused *control.Error
	if err == nil || !strings.HasPrefix(err.Error(), "control: ") || errors.As(err, &refused) {
		t.Errorf("Reset of a server that has gone = %v, want the connection error", err)
	}
}
