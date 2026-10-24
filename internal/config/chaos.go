package config

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sshfront"
)

// chaosConfig is a chaos preset over a scope, with the extras it opts in
// to.
type chaosConfig struct {
	Preset string      `yaml:"preset" json:"preset"`
	Scope  scopeConfig `yaml:"scope,flow" json:"scope"`
	Extras []string    `yaml:"extras,flow" json:"extras"`
	Paused bool        `yaml:"paused" json:"paused"`
}

// chaos returns the chaos that cc gives. Its scope may refer only to users,
// and keys, that users has.
func (cc chaosConfig) chaos(users []sshfront.User) (*faults.Chaos, error) {
	scope, err := cc.Scope.match().match(users, false)
	if err != nil {
		return nil, fmt.Errorf("scope: %w", err)
	}
	c := &faults.Chaos{
		Preset: faults.Preset(cc.Preset),
		Scope:  faults.Scope{User: scope.User, KeyFingerprint: scope.KeyFingerprint, Path: scope.Path},
		Paused: cc.Paused,
	}
	for _, x := range cc.Extras {
		c.Extras = append(c.Extras, faults.Extra(x))
	}
	if err := c.Check(); err != nil {
		return nil, err
	}
	return c, nil
}

// ParseChaos reads chaos from data, in JSON, as a scenario's chaos gives
// it, and validates it as Load does. Its scope may refer only to users, and
// keys, that users has.
func ParseChaos(data []byte, users []sshfront.User) (*faults.Chaos, error) {
	var cc chaosConfig
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cc); err != nil {
		return nil, fmt.Errorf("chaos: %w", err)
	}
	c, err := cc.chaos(users)
	if err != nil {
		return nil, fmt.Errorf("chaos: %w", err)
	}
	return c, nil
}

// ChaosJSON returns c in JSON, with every default spelled out, which
// ParseChaos reads as the same chaos.
func ChaosJSON(c *faults.Chaos) ([]byte, error) {
	b, err := json.Marshal(longChaos(c))
	if err != nil {
		return nil, fmt.Errorf("config: write the chaos: %w", err)
	}
	return b, nil
}

// longChaos returns c with every default spelled out.
func longChaos(c *faults.Chaos) *chaosConfig {
	cc := &chaosConfig{
		Preset: string(c.Preset),
		Scope:  scopeConfig{User: c.Scope.User, KeyFingerprint: c.Scope.KeyFingerprint},
		Extras: []string{},
		Paused: c.Paused,
	}
	s := &cc.Scope
	setLocation(c.Scope.Path, &s.Path, &s.PathPrefix, &s.PathGlob, &s.Filename, &s.FilenameGlob)
	for _, x := range c.Extras {
		cc.Extras = append(cc.Extras, string(x))
	}
	return cc
}
