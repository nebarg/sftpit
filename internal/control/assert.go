package control

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

const (
	// defaultDrainWait is how long a drain waits for file handles to close
	// if its request does not say.
	defaultDrainWait = 10 * time.Second

	// maxDrainWait bounds what a request can ask for.
	maxDrainWait = 10 * time.Minute
)

// DrainRequest is the body of a drain or an assert. Timeout is how long to
// wait for file handles to close, as a duration such as 10s, or 10s if it
// is "".
type DrainRequest struct {
	Timeout string `json:"timeout,omitempty"`
}

// drainWait returns the wait that the body of r asks for, having answered
// the request if it asks for one that cannot be.
func drainWait(w http.ResponseWriter, r *http.Request) (time.Duration, bool) {
	var body DrainRequest
	if !decodeBody(w, r, &body) {
		return 0, false
	}
	if body.Timeout == "" {
		return defaultDrainWait, true
	}
	wait, err := time.ParseDuration(body.Timeout)
	if err != nil || wait < 0 || wait > maxDrainWait {
		writeError(w, http.StatusBadRequest, fmt.Errorf("timeout %q is not a duration of up to %s, such as 10s", body.Timeout, maxDrainWait))
		return 0, false
	}
	return wait, true
}

// drainContext returns the context of a drain that waits for wait, which
// runs to its end even if the client goes away, as a reset does, since
// stopping part way would leave admission closed with nothing to say so.
func drainContext(r *http.Request, wait time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), wait+resetTimeout)
}

// drain ends a run's clients, and answers with what they left unfinished.
func (a *api) drain(w http.ResponseWriter, r *http.Request) {
	wait, ok := drainWait(w, r)
	if !ok {
		return
	}
	ctx, cancel := drainContext(r, wait)
	defer cancel()
	drained, err := a.runs.Drain(ctx, r.PathValue("id"), wait)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	unfinished := drained.Unfinished
	if unfinished == nil {
		unfinished = []string{}
	}
	writeJSON(w, http.StatusOK, struct {
		Unfinished []string `json:"unfinished"`
	}{unfinished})
}

// assert drains a run and answers with the verdict on it, with status 200
// whether it passed or failed.
func (a *api) assert(w http.ResponseWriter, r *http.Request) {
	wait, ok := drainWait(w, r)
	if !ok {
		return
	}
	ctx, cancel := drainContext(r, wait)
	defer cancel()
	report, err := a.runs.Assert(ctx, r.PathValue("id"), wait)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// report answers with the report of a run that has been asserted.
func (a *api) report(w http.ResponseWriter, r *http.Request) {
	run := r.PathValue("id")
	f, err := a.runs.OpenReport(run)
	if err != nil {
		writeError(w, fileStatus(err), err)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	serveDownload(w, r, "report-"+run+".json", "application/json", info.ModTime(), f)
}
