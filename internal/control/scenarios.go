package control

import (
	"errors"
	"net/http"

	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/runs"
)

// Scenario is a scenario as the API gives it: its name, where it is
// defined, whether it is on in the current run, and its faults, with their
// presets and defaults filled in. A saved scenario whose file holds no
// valid scenario has an error and no faults.
type Scenario struct {
	Name        string         `json:"name"`
	Source      config.Source  `json:"source"`
	On          bool           `json:"on"`
	Description string         `json:"description,omitempty"`
	Faults      []config.Fault `json:"faults"`
	Error       string         `json:"error,omitempty"`
}

func newScenario(s runs.Scenario) Scenario {
	body := Scenario{Name: s.Name, Source: s.Source, On: s.On, Description: s.Scenario.Description, Faults: []config.Fault{}}
	if s.Err != nil {
		body.Error = s.Err.Error()
		return body
	}
	resolved, err := s.Scenario.Resolved()
	if err != nil {
		body.Error = err.Error()
		return body
	}
	body.Faults = resolved.Faults
	return body
}

func (a *api) scenarios(w http.ResponseWriter, _ *http.Request) {
	list, err := a.runs.Scenarios()
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	described := make([]Scenario, len(list))
	for i, s := range list {
		described[i] = newScenario(s)
	}
	writeJSON(w, http.StatusOK, map[string]any{"scenarios": described})
}

func (a *api) switchScenario(w http.ResponseWriter, r *http.Request) {
	var body struct {
		On *bool `json:"on"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if body.On == nil {
		writeError(w, http.StatusBadRequest, errors.New("on is required: true to turn the scenario on, false to turn it off"))
		return
	}
	s, err := a.runs.SwitchScenario(r.PathValue("name"), *body.On)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, newScenario(s))
}

func (a *api) saveScenario(w http.ResponseWriter, r *http.Request) {
	var sc config.Scenario
	if !decodeBody(w, r, &sc) {
		return
	}
	s, err := a.runs.SaveScenario(r.PathValue("name"), sc)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, newScenario(s))
}

func (a *api) deleteScenario(w http.ResponseWriter, r *http.Request) {
	if err := a.runs.DeleteScenario(r.PathValue("name")); err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
