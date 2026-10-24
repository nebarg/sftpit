package config

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sshfront"
)

// ParseRules reads rules from data, a JSON list of rules as a scenario's
// faults gives them, in the long form or as recipes, and validates them as
// Load does. They may refer only to users, and keys, that users has.
func ParseRules(data []byte, users []sshfront.User) ([]faults.Rule, error) {
	var list []json.RawMessage
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("faults: %w", err)
	}
	rcs := make([]ruleConfig, len(list))
	for i, raw := range list {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rcs[i]); err != nil {
			return nil, fmt.Errorf("faults[%d]: %w", i, err)
		}
	}
	rules, err := parseRules("", rcs, users)
	if err != nil {
		return nil, err
	}
	if err := faults.Check(rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// RulesJSON returns rules as a JSON list, in the order given, each in the
// long form with every default spelled out, which ParseRules reads as the
// same rules.
func RulesJSON(rules []faults.Rule) ([]byte, error) {
	long := make([]ruleConfig, 0, len(rules))
	for _, r := range rules {
		long = append(long, longForm(r))
	}
	b, err := json.Marshal(long)
	if err != nil {
		return nil, fmt.Errorf("config: write the rules: %w", err)
	}
	return b, nil
}
