package control

import (
	"cmp"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/faults"
)

// Scenario describes a scenario in a reply: one the configuration file
// defines, which only an edit of that file changes, or a scenario file.
type Scenario struct {
	Name string `json:"name"`

	// Source is "config" or "file".
	Source string `json:"source"`

	// Path and Hash are a scenario file's absolute path and the SHA-256 of
	// its content, which a save that replaces it gives.
	Path string `json:"path,omitempty"`
	Hash string `json:"hash,omitempty"`

	// Error says why a scenario file holds no valid scenario, which leaves
	// the fields that follow unset.
	Error string `json:"error,omitempty"`

	Description string          `json:"description,omitempty"`
	Seed        *Seed           `json:"seed,omitempty"`
	Faults      json.RawMessage `json:"faults,omitempty"`
	Chaos       json.RawMessage `json:"chaos,omitempty"`
}

// SaveScenarioRequest is the body of a save of a scenario file. Hash is
// the hash of the file that the save replaces, as a listing gave it, and
// is "" for a new file. The other fields give the scenario as a reset's
// inline scenario does, with a description and a seed to pin.
type SaveScenarioRequest struct {
	Hash        string `json:"hash,omitempty"`
	Description string `json:"description,omitempty"`
	Seed        *Seed  `json:"seed,omitempty"`
	RulesRequest
}

// scenarios answers with the configuration's scenarios and the scenario
// files, sorted by name, and the directory that holds the files.
func (a *api) scenarios(w http.ResponseWriter, _ *http.Request) {
	all, err := a.runs.Scenarios()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	body := struct {
		Dir       string     `json:"dir"`
		Scenarios []Scenario `json:"scenarios"`
	}{Dir: all.Dir, Scenarios: []Scenario{}}
	for name, s := range all.Configured {
		described, err := describeScenario(Scenario{Name: name, Source: "config"}, s)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		body.Scenarios = append(body.Scenarios, described)
	}
	for _, f := range all.Files {
		described, err := describeFile(f)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		body.Scenarios = append(body.Scenarios, described)
	}
	slices.SortStableFunc(body.Scenarios, func(a, b Scenario) int {
		return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.Source, b.Source))
	})
	writeJSON(w, http.StatusOK, body)
}

// saveScenario saves a scenario file, answering 201 for a new file and 200
// for one replaced.
func (a *api) saveScenario(w http.ResponseWriter, r *http.Request) {
	var body SaveScenarioRequest
	if !decodeBody(w, r, &body) {
		return
	}
	rules, chaos, err := a.parseRules(body.RulesRequest)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s := config.Scenario{Description: body.Description, Seed: (*faults.Seed)(body.Seed), Rules: rules, Chaos: chaos}
	file, err := a.runs.SaveScenario(r.PathValue("name"), s, body.Hash)
	if err != nil {
		writeError(w, scenarioStatus(err), err)
		return
	}
	described, err := describeFile(file)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	code := http.StatusOK
	if body.Hash == "" {
		code = http.StatusCreated
	}
	writeJSON(w, code, described)
}

// scenarioStatus returns the HTTP status that answers err from saving a
// scenario file.
func scenarioStatus(err error) int {
	switch {
	case errors.Is(err, config.ErrScenarioName):
		return http.StatusBadRequest
	case errors.Is(err, config.ErrConfiguredScenario), errors.Is(err, config.ErrScenarioChanged):
		return http.StatusConflict
	}
	return statusFor(err)
}

// describeFile describes the scenario file f.
func describeFile(f config.ScenarioFile) (Scenario, error) {
	d := Scenario{Name: f.Name, Source: "file", Path: f.Path, Hash: f.Hash}
	if f.Err != nil {
		d.Error = f.Err.Error()
		return d, nil //nolint:nilerr // A listing reports a bad file in its reply.
	}
	return describeScenario(d, f.Scenario)
}

// describeScenario returns d with the description, seed, rules and chaos of
// s, its rules in the long form, in the order given.
func describeScenario(d Scenario, s config.Scenario) (Scenario, error) {
	d.Description, d.Seed = s.Description, (*Seed)(s.Seed)
	var err error
	if d.Faults, err = config.RulesJSON(s.Rules); err != nil {
		return Scenario{}, err
	}
	if s.Chaos != nil {
		if d.Chaos, err = config.ChaosJSON(s.Chaos); err != nil {
			return Scenario{}, err
		}
	}
	return d, nil
}
