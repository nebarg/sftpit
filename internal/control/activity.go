package control

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/nebarg/sftpit/internal/activity"
)

const (
	defaultActivityLines = 500
	maxActivityLines     = 5000
)

// Activity is what clients of the current run did, as lines.
type Activity struct {
	// Lines are the latest lines, oldest first.
	Lines []activity.Line `json:"lines"`

	// LastEvent is the ID of the latest event the lines include, which
	// changes whenever they may have.
	LastEvent uint64 `json:"last_event"`

	// Partial is set once the run has more events than are kept, so the
	// earliest lines are gone and the first may lack its start.
	Partial bool `json:"partial"`
}

// activity answers with the current run's activity: its latest lines, up
// to limit, 500 by default.
func (a *api) activity(w http.ResponseWriter, r *http.Request) {
	limit := defaultActivityLines
	if s := r.URL.Query().Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > maxActivityLines {
			writeError(w, http.StatusBadRequest, fmt.Errorf("limit %q is not a number from 1 to %d", s, maxActivityLines))
			return
		}
		limit = n
	}
	page := a.runs.Events().Events()
	names := make(map[string]string)
	for _, f := range a.runs.Faults() {
		names[f.ID] = f.Spec.Name
	}
	lines := activity.Lines(page.Events, names)
	lines = lines[max(0, len(lines)-limit):]
	writeJSON(w, http.StatusOK, Activity{Lines: lines, LastEvent: page.Last, Partial: page.First > 1})
}
