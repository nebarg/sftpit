package control

import (
	"context"
	"errors"
	"net/http"

	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/runs"
)

// Fault is a fault of the current run as the API gives it: its ID, whether
// it is on, how many times it has happened since it was switched on, and
// the fault in plain terms, with its preset and defaults filled in.
type Fault struct {
	ID       string `json:"id"`
	On       bool   `json:"on"`
	Happened uint64 `json:"happened"`
	config.Fault
}

func newFault(f runs.Fault) Fault {
	return Fault{ID: f.ID, On: f.On, Happened: f.Happened, Fault: f.Spec}
}

// presets answers with what a fault can be made of: the presets, the steps
// and actions of a custom fault, and the errors a refusal can answer with.
func (a *api) presets(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"presets": config.Presets,
		"steps":   config.Steps,
		"actions": config.Actions,
		"errors":  config.ErrorNames(),
	})
}

func (a *api) faults(w http.ResponseWriter, _ *http.Request) {
	list := a.runs.Faults()
	described := make([]Fault, len(list))
	for i, f := range list {
		described[i] = newFault(f)
	}
	writeJSON(w, http.StatusOK, map[string]any{"faults": described})
}

func (a *api) fault(w http.ResponseWriter, r *http.Request) {
	f, err := a.runs.Fault(r.PathValue("id"))
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, newFault(f))
}

func (a *api) addFault(w http.ResponseWriter, r *http.Request) {
	var spec config.Fault
	if !decodeBody(w, r, &spec) {
		return
	}
	// A fault that can never work is the caller's mistake, whatever the
	// run is doing.
	if _, err := spec.Rule("check", a.runs.Users()); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	f, err := a.runs.AddFault(spec)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusCreated, newFault(f))
}

func (a *api) switchFault(w http.ResponseWriter, r *http.Request) {
	var body struct {
		On *bool `json:"on"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if body.On == nil {
		writeError(w, http.StatusBadRequest, errors.New("on is required: true to switch the fault on, false to switch it off"))
		return
	}
	f, err := a.runs.SwitchFault(r.PathValue("id"), *body.On)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, newFault(f))
}

func (a *api) removeFault(w http.ResponseWriter, r *http.Request) {
	if err := a.runs.RemoveFault(r.PathValue("id")); err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) removeFaults(w http.ResponseWriter, _ *http.Request) {
	if err := a.runs.RemoveFaults(); err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// startAgain switches every fault off, the scenario's included, and puts
// the starting files back, by starting a run without a scenario.
func (a *api) startAgain(w http.ResponseWriter, r *http.Request) {
	// It takes no fields, but an empty body or {} will do.
	if !decodeBody(w, r, &struct{}{}) {
		return
	}
	none := ""
	// A reset runs to its end even if the client goes away, as stopping
	// part way would leave admission closed.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), resetTimeout)
	defer cancel()
	if _, err := a.runs.Reset(ctx, runs.ResetRequest{Scenario: &none}); err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
