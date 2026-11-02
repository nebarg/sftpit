package control

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nebarg/sftpit/internal/events"
)

const (
	// defaultEvents and maxEvents are the default and largest number of
	// events in a page of a run's history.
	defaultEvents = 500
	maxEvents     = 5000

	// keepaliveInterval is how often an idle stream of events sends a
	// comment, so that proxies keep the connection open.
	keepaliveInterval = 15 * time.Second
)

// events answers with a page of a run's events, or, for a client that
// accepts text/event-stream, streams them as server-sent events.
func (a *api) events(w http.ResponseWriter, r *http.Request) {
	rec, err := a.runs.Events(r.PathValue("id"))
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	q, err := parseEventQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		stream(w, r, rec, q)
		return
	}
	writeJSON(w, http.StatusOK, rec.Events(q.after, q.limit, q.filter))
}

// eventQuery is what a request for events asks for: those after an ID that
// a filter matches, up to a limit.
type eventQuery struct {
	after  uint64
	limit  int
	filter events.Filter
}

// parseEventQuery reads the query of a request for events: after, limit,
// kind, as a list separated by commas or given more than once, connection,
// user, path and rule. A stream resumes after its Last-Event-ID.
func parseEventQuery(r *http.Request) (eventQuery, error) {
	values := r.URL.Query()
	q := eventQuery{limit: defaultEvents}
	var err error
	if after := cmp.Or(r.Header.Get("Last-Event-ID"), values.Get("after")); after != "" {
		if q.after, err = strconv.ParseUint(after, 10, 64); err != nil {
			return q, fmt.Errorf("after %q is not an event ID", after)
		}
	}
	if limit := values.Get("limit"); limit != "" {
		if q.limit, err = strconv.Atoi(limit); err != nil || q.limit < 1 || q.limit > maxEvents {
			return q, fmt.Errorf("limit %q is not a number from 1 to %d", limit, maxEvents)
		}
	}
	for _, kinds := range values["kind"] {
		for kind := range strings.SplitSeq(kinds, ",") {
			q.filter.Kinds = append(q.filter.Kinds, events.Kind(kind))
		}
	}
	if conn := values.Get("connection"); conn != "" {
		if q.filter.Connection, err = strconv.ParseUint(conn, 10, 64); err != nil {
			return q, fmt.Errorf("connection %q is not a connection ID", conn)
		}
	}
	q.filter.User, q.filter.Path, q.filter.Rule = values.Get("user"), values.Get("path"), values.Get("rule")
	return q, nil
}

// stream sends the events that q asks for as server-sent events, each with
// its ID, followed by the run's events as they are recorded, until the
// client goes away or the run ends. A gap event says that events the
// client asked for are gone, and an end event that the run has ended.
func stream(w http.ResponseWriter, r *http.Request, rec *events.Recorder, q eventQuery) {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	keepalive := time.NewTicker(keepaliveInterval)
	defer keepalive.Stop()
	after := q.after
	for {
		changed, ended := rec.Changed(), rec.Closed()
		page := rec.Events(after, q.limit, q.filter)
		if after+1 < page.First {
			gap, _ := json.Marshal(map[string]uint64{"after": after, "first_id": page.First})
			fmt.Fprintf(w, "event: gap\ndata: %s\n\n", gap)
		}
		for _, e := range page.Events {
			data, err := json.Marshal(e)
			if err != nil {
				return
			}
			fmt.Fprintf(w, "id: %d\ndata: %s\n\n", e.ID, data)
		}
		after = page.Next
		if len(page.Events) == q.limit {
			continue
		}
		if ended {
			fmt.Fprint(w, "event: end\ndata: {}\n\n")
			rc.Flush()
			return
		}
		if rc.Flush() != nil {
			return
		}
		select {
		case <-changed:
		case <-keepalive.C:
			fmt.Fprint(w, ": keepalive\n\n")
		case <-r.Context().Done():
			return
		}
	}
}
