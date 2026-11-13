// Package control serves sftpit's API over HTTP: the faults of the current
// run, which can be added, turned on and off and removed, the scenarios,
// which turn groups of faults on and off and can be saved, what clients did,
// the run's files, how to connect, the server's status, the release of
// held requests, and resets that turn every fault off and restore the
// starting files. It serves the dashboard, which uses the API, too.
//
// The API answers only requests addressed to a loopback host, or to a host
// name it is given, such as a compose service's, so a web page cannot reach
// it through DNS rebinding. It refuses a change that a browser
// makes from another origin, and any change without the RequestHeader
// header, which a page on another origin cannot send without a CORS
// preflight that the API never allows.
package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/runs"
)

// RequestHeader must be set, to any non-empty value, on every request that
// changes something.
const RequestHeader = "Sftpit-Control"

const (
	// resetTimeout bounds how long a reset waits for the sessions of the
	// run it ends to finish.
	resetTimeout = 30 * time.Second

	// maxBodyBytes bounds a request body.
	maxBodyBytes = 64 << 10
)

// Handler returns the control API and the dashboard for the runs that m
// manages. It answers requests addressed to localhost, a loopback address or
// one of opts.Hosts.
func Handler(m *runs.Manager, opts Options) http.Handler {
	a := &api{runs: m, opts: opts}
	mux := http.NewServeMux()
	ui := dashboard()
	mux.Handle("GET /{$}", ui)
	mux.Handle("GET /ui/", http.StripPrefix("/ui", ui))
	mux.HandleFunc("GET /api/presets", a.presets)
	mux.HandleFunc("GET /api/faults", a.faults)
	mux.HandleFunc("POST /api/faults", a.addFault)
	mux.HandleFunc("DELETE /api/faults", a.removeFaults)
	mux.HandleFunc("GET /api/faults/{id}", a.fault)
	mux.HandleFunc("PATCH /api/faults/{id}", a.switchFault)
	mux.HandleFunc("DELETE /api/faults/{id}", a.removeFault)
	mux.HandleFunc("GET /api/scenarios", a.scenarios)
	mux.HandleFunc("PATCH /api/scenarios/{name}", a.switchScenario)
	mux.HandleFunc("PUT /api/scenarios/{name}", a.saveScenario)
	mux.HandleFunc("DELETE /api/scenarios/{name}", a.deleteScenario)
	mux.HandleFunc("POST /api/reset", a.startAgain)
	mux.HandleFunc("GET /api/activity", a.activity)
	mux.HandleFunc("GET /api/server", a.server)
	mux.HandleFunc("GET /api/status", a.status)
	mux.HandleFunc("GET /api/files", a.files)
	mux.HandleFunc("GET /api/files/content", a.fileContent)
	mux.HandleFunc("POST /api/release", a.releaseStalls)
	return protect(mux, opts.Hosts)
}

type api struct {
	runs *runs.Manager
	opts Options
}

func (a *api) status(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, newStatus(a.runs.Status()))
}

// statusFor returns the HTTP status that answers err from the runs.
func statusFor(err error) int {
	switch {
	case errors.Is(err, config.ErrFixedScenario):
		return http.StatusConflict
	case errors.Is(err, config.ErrInvalidScenario):
		return http.StatusBadRequest
	case errors.Is(err, runs.ErrUnknownFault), errors.Is(err, config.ErrUnknownScenario):
		return http.StatusNotFound
	}
	return http.StatusInternalServerError
}

func (a *api) releaseStalls(w http.ResponseWriter, _ *http.Request) {
	a.runs.ReleaseStalls()
	writeJSON(w, http.StatusOK, newStatus(a.runs.Status()))
}

// Status is the reply to a status request or a release of held requests.
type Status struct {
	SFTP SFTPStatus `json:"sftp"`
	Run  RunStatus  `json:"run"`
}

// SFTPStatus says whether clients can reach the current run.
type SFTPStatus struct {
	State     runs.State `json:"state"`
	DownUntil time.Time  `json:"down_until,omitzero"`
	Error     string     `json:"error,omitempty"`
}

// RunStatus describes the current run: its ID, how many requests and
// replies holds are holding, and how many connections freezes are holding.
type RunStatus struct {
	ID      string `json:"id"`
	Stalled int    `json:"stalled"`
	Frozen  int    `json:"frozen"`
}

func newStatus(s runs.Status) Status {
	body := Status{
		SFTP: SFTPStatus{State: s.State, DownUntil: s.DownUntil.UTC()},
		Run:  RunStatus{ID: s.Run.ID, Stalled: s.Stalled, Frozen: s.Frozen},
	}
	if s.Err != nil {
		body.SFTP.Error = s.Err.Error()
	}
	return body
}

// decodeBody decodes the JSON body of r into v, which an empty body leaves
// as it is, and reports whether it could. If it could not, it has answered
// the request: 413 for a body over maxBodyBytes, and 400 otherwise.
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	if err == nil {
		if err = dec.Decode(new(json.RawMessage)); errors.Is(err, io.EOF) {
			err = nil
		} else if _, tooLarge := errors.AsType[*http.MaxBytesError](err); !tooLarge {
			err = errors.New("expected a single JSON object")
		}
	}
	if err == nil {
		return true
	}
	code := http.StatusBadRequest
	if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
		code = http.StatusRequestEntityTooLarge
	}
	writeError(w, code, fmt.Errorf("invalid request body: %w", err))
	return false
}

// protect refuses a request addressed to a host other than a loopback one
// or one of hosts, and a change that a browser makes from another origin or
// that lacks RequestHeader.
func protect(next http.Handler, hosts []string) http.Handler {
	crossOrigin := http.NewCrossOriginProtection()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !allowedHost(r.Host, hosts) {
			writeError(w, http.StatusForbidden, fmt.Errorf("host %q is not a loopback host or one given with --control-host", r.Host))
			return
		}
		if err := crossOrigin.Check(r); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		if !isSafe(r.Method) && r.Header.Get(RequestHeader) == "" {
			writeError(w, http.StatusForbidden, fmt.Errorf("a %s needs a non-empty %s header", r.Method, RequestHeader))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// allowedHost reports whether the host of a Host header, with or without
// its port, is localhost, a loopback address or one of hosts.
func allowedHost(hostport string, hosts []string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if strings.EqualFold(host, "localhost") || slices.ContainsFunc(hosts, func(h string) bool { return strings.EqualFold(h, host) }) {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func isSafe(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

func writeError(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	// The status has gone, so a body that fails to follow cannot be
	// reported to the client.
	_ = json.NewEncoder(w).Encode(v)
}
