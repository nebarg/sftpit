package control

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/runs"
)

// RulesRequest is the body of a request that gives rules and chaos, as a
// change of rules does: the rules, required, and the chaos, if any.
type RulesRequest struct {
	Faults json.RawMessage `json:"faults"`
	Chaos  json.RawMessage `json:"chaos,omitempty"`
}

// QueueRequest is the body of a request that queues the next run: its rules
// and chaos, as a change of rules gives them, and its assertions.
type QueueRequest struct {
	RulesRequest
	Assertions json.RawMessage `json:"assertions,omitempty"`
}

// next answers with the rules and chaos queued for the next reset, or 404
// if none are.
func (a *api) next(w http.ResponseWriter, _ *http.Request) {
	queued := a.runs.Queued()
	if queued == nil {
		writeError(w, http.StatusNotFound, errors.New("nothing is queued: the next reset repeats the current scenario"))
		return
	}
	writeScenarioRules(w, queued.Rules, queued.Chaos, queued.Assertions)
}

// queue queues rules and chaos for the next reset that names no scenario
// and gives none inline, and answers with them in the long form.
func (a *api) queue(w http.ResponseWriter, r *http.Request) {
	var body QueueRequest
	if !decodeBody(w, r, &body) {
		return
	}
	rules, chaos, err := a.parseRules(body.RulesRequest)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	assertions, err := a.assertions(body.Assertions, rules, chaos)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := a.runs.Queue(&runs.InlineScenario{Rules: rules, Chaos: chaos, Assertions: assertions}); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeScenarioRules(w, rules, chaos, assertions)
}

// unqueue clears what is queued, and answers with the status.
func (a *api) unqueue(w http.ResponseWriter, _ *http.Request) {
	if err := a.runs.Queue(nil); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, newStatus(a.runs.Status()))
}

// checkRules validates rules and chaos, as a change of rules would, without
// applying them, and answers with them in the long form, recipes expanded,
// as the engine would run them.
func (a *api) checkRules(w http.ResponseWriter, r *http.Request) {
	var body RulesRequest
	if !decodeBody(w, r, &body) {
		return
	}
	rules, chaos, err := a.parseRules(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeScenarioRules(w, rules, chaos, nil)
}

// assertions returns the assertions that raw gives, if any, which may refer
// to the rules of rules and chaos.
func (a *api) assertions(raw json.RawMessage, rules []faults.Rule, chaos *faults.Chaos) ([]config.Assertion, error) {
	if !given(raw) {
		return nil, nil
	}
	return config.ParseAssertions(raw, rules, chaos, a.runs.ExpectedDir())
}

// parseRules returns the rules and chaos that body gives, validated as the
// configuration's are.
func (a *api) parseRules(body RulesRequest) ([]faults.Rule, *faults.Chaos, error) {
	if !given(body.Faults) {
		return nil, nil, errors.New("faults is required: the list of rules, or [] for none")
	}
	rules, err := config.ParseRules(body.Faults, a.runs.Users())
	if err != nil {
		return nil, nil, err
	}
	chaos, err := a.chaos(body.Chaos)
	if err != nil {
		return nil, nil, err
	}
	return rules, chaos, nil
}

// writeScenarioRules answers with rules and chaos in the long form, as a
// run's rules are given, with the rules each chaos compiles to, and with
// any assertions.
func writeScenarioRules(w http.ResponseWriter, rules []faults.Rule, chaos *faults.Chaos, assertions []config.Assertion) {
	body := struct {
		Faults        json.RawMessage `json:"faults"`
		Chaos         json.RawMessage `json:"chaos,omitempty"`
		CompiledChaos json.RawMessage `json:"compiled_chaos,omitempty"`
		Assertions    json.RawMessage `json:"assertions,omitempty"`
	}{}
	var err error
	if body.Faults, err = config.RulesJSON(rules); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if chaos != nil {
		if body.Chaos, err = config.ChaosJSON(chaos); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if body.CompiledChaos, err = config.RulesJSON(chaos.Rules()); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	if len(assertions) > 0 {
		if body.Assertions, err = config.AssertionsJSON(assertions); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, body)
}
