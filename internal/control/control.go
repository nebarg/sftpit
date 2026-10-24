// Package control serves sftpit's control API over HTTP: whether sftpit is
// alive and ready, the status of the current run, its rules, which can
// change during the run, and resets that start the next run. Its Client
// calls the API.
//
// The API answers only requests addressed to a loopback host, so a web page
// cannot reach it through DNS rebinding. It refuses a change that a browser
// makes from another origin, and any change without the RequestHeader
// header, which a page on another origin cannot send without a CORS
// preflight that the API never allows.
package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/runs"
)

// RequestHeader must be set, to any value, on every request that changes
// something.
const RequestHeader = "Sftpit-Control"

const (
	// resetTimeout bounds how long a reset waits for the sessions of the
	// run it ends to finish.
	resetTimeout = 30 * time.Second

	// maxBodyBytes bounds a request body.
	maxBodyBytes = 64 << 10
)

// Handler returns the control API for the runs that m manages.
func Handler(m *runs.Manager) http.Handler {
	a := &api{runs: m}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", a.health)
	mux.HandleFunc("GET /api/v1/ready", a.ready)
	mux.HandleFunc("GET /api/v1/status", a.status)
	mux.HandleFunc("POST /api/v1/reset", a.reset)
	mux.HandleFunc("GET /api/v1/runs/{id}/rules", a.rules)
	mux.HandleFunc("PUT /api/v1/runs/{id}/rules", a.changeRules)
	return protect(mux)
}

type api struct {
	runs *runs.Manager
}

func (a *api) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ready reports whether the runs can be used, which they cannot once a
// reset has failed, until another succeeds.
func (a *api) ready(w http.ResponseWriter, _ *http.Request) {
	if err := a.runs.Status().Err; err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ready": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ready": true})
}

func (a *api) status(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, newStatus(a.runs.Status()))
}

func (a *api) reset(w http.ResponseWriter, r *http.Request) {
	var body ResetRequest
	if err := decodeBody(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// A reset runs to its end even if the client goes away, as stopping
	// part way would leave admission closed.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), resetTimeout)
	defer cancel()
	_, err := a.runs.Reset(ctx, runs.ResetRequest{Run: body.Run, Scenario: body.Scenario, Seed: (*faults.Seed)(body.Seed)})
	switch {
	case errors.Is(err, runs.ErrStaleRun):
		writeError(w, http.StatusConflict, err)
	case errors.Is(err, runs.ErrUnknownScenario), errors.Is(err, runs.ErrSeedWithoutScenario):
		writeError(w, http.StatusBadRequest, err)
	case err != nil:
		writeError(w, http.StatusInternalServerError, err)
	default:
		writeJSON(w, http.StatusOK, newStatus(a.runs.Status()))
	}
}

func (a *api) rules(w http.ResponseWriter, r *http.Request) {
	set, err := a.runs.Rules(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	writeRules(w, set)
}

func (a *api) changeRules(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Revision *uint64         `json:"revision"`
		Faults   json.RawMessage `json:"faults"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	switch {
	case body.Revision == nil:
		writeError(w, http.StatusBadRequest, errors.New("revision is required: the revision of the rules that the change replaces"))
		return
	case len(body.Faults) == 0 || string(body.Faults) == "null":
		writeError(w, http.StatusBadRequest, errors.New("faults is required: the list of rules, or [] for none"))
		return
	}
	rules, err := config.ParseRules(body.Faults, a.runs.Users())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	set, err := a.runs.ChangeRules(r.PathValue("id"), *body.Revision, rules)
	switch {
	case errors.Is(err, runs.ErrStaleRun), errors.Is(err, faults.ErrStaleRevision):
		writeError(w, http.StatusConflict, err)
	case err != nil:
		writeError(w, http.StatusInternalServerError, err)
	default:
		writeRules(w, set)
	}
}

// writeRules writes set as the reply to a request for a run's rules or a
// change of them: the revision, the rules in the long form, in the order
// they are tried, and what each has done, by rule ID.
func writeRules(w http.ResponseWriter, set faults.RuleSet) {
	rules, err := config.RulesJSON(set.Rules)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	counts := make(map[string]ruleCounts, len(set.Counts))
	for id, c := range set.Counts {
		counts[id] = ruleCounts{Matched: c.Matched, Selected: c.Selected, Fired: c.Fired}
	}
	writeJSON(w, http.StatusOK, struct {
		Revision uint64                `json:"revision"`
		Faults   json.RawMessage       `json:"faults"`
		Counts   map[string]ruleCounts `json:"counts"`
	}{set.Revision, rules, counts})
}

// ruleCounts are what a rule has done in the run, as faults.Counts.
type ruleCounts struct {
	Matched  uint64 `json:"matched"`
	Selected uint64 `json:"selected"`
	Fired    uint64 `json:"fired"`
}

// ResetRequest is the body of a reset, which chooses the next run as
// runs.ResetRequest does. Every field is optional, so an empty body repeats
// the current run.
type ResetRequest struct {
	Run      string  `json:"run,omitempty"`
	Scenario *string `json:"scenario,omitempty"`
	Seed     *Seed   `json:"seed,omitempty"`
}

// Status is the reply to a status request or a reset.
type Status struct {
	SFTP    SFTPStatus `json:"sftp"`
	Backend string     `json:"backend"`
	Run     RunStatus  `json:"run"`
}

// SFTPStatus says whether clients can reach the current run.
type SFTPStatus struct {
	State     runs.State `json:"state"`
	DownUntil *time.Time `json:"down_until,omitempty"`
	Error     string     `json:"error,omitempty"`
}

// RunStatus describes the current run: the scenario it started with, if
// any, its seed and the revision of its rules.
type RunStatus struct {
	ID         string `json:"id"`
	Scenario   string `json:"scenario,omitempty"`
	Seed       Seed   `json:"seed"`
	SeedPinned bool   `json:"seed_pinned,omitempty"`
	Revision   uint64 `json:"revision"`
}

func newStatus(s runs.Status) Status {
	body := Status{
		SFTP:    SFTPStatus{State: s.State},
		Backend: "embedded",
		Run:     RunStatus{ID: s.Run.ID},
	}
	if !s.DownUntil.IsZero() {
		until := s.DownUntil.UTC()
		body.SFTP.DownUntil = &until
	}
	if s.Err != nil {
		body.SFTP.Error = s.Err.Error()
	}
	sc := s.Run.Scenario
	body.Run.Scenario, body.Run.Seed, body.Run.SeedPinned, body.Run.Revision = sc.Name, Seed(sc.Seed), sc.Pinned, s.Revision
	return body
}

// Seed is a faults.Seed in JSON. It is written as a decimal string, as the
// proto3 JSON mapping writes a uint64, since JavaScript reads a number past
// 2^53 inexactly, and read from a string or a number.
type Seed faults.Seed

func (s Seed) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatUint(uint64(s), 10))
}

func (s *Seed) UnmarshalJSON(b []byte) error {
	text := string(b)
	if strings.HasPrefix(text, `"`) {
		if err := json.Unmarshal(b, &text); err != nil {
			return err
		}
	}
	n, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return errors.New("a seed is a whole number from 0 to 18446744073709551615")
	}
	*s = Seed(n)
	return nil
}

// decodeBody decodes the JSON body of r into v, which an empty body leaves
// as it is.
func decodeBody(w http.ResponseWriter, r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("invalid request body: %w", err)
	}
	if dec.More() {
		return errors.New("invalid request body: expected a single JSON object")
	}
	return nil
}

// protect refuses a request addressed to a host other than a loopback one,
// and a change that a browser makes from another origin or that lacks
// RequestHeader.
func protect(next http.Handler) http.Handler {
	crossOrigin := http.NewCrossOriginProtection()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !isLoopbackHost(r.Host) {
			writeError(w, http.StatusForbidden, fmt.Errorf("host %q is not a loopback host", r.Host))
			return
		}
		if err := crossOrigin.Check(r); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		if !isSafe(r.Method) && r.Header.Get(RequestHeader) == "" {
			writeError(w, http.StatusForbidden, fmt.Errorf("a %s needs the %s header", r.Method, RequestHeader))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isLoopbackHost reports whether the host of a Host header, with or without
// its port, is localhost or a loopback address.
func isLoopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
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
	json.NewEncoder(w).Encode(v)
}
