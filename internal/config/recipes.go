package config

import (
	"cmp"
	"errors"
	"fmt"
	"reflect"
	"slices"
)

// scopeConfig holds the fields with which a recipe or a chaos narrows the
// requests it applies to. They mean what they mean in a match.
type scopeConfig struct {
	User           string `yaml:"user,omitempty" json:"user,omitempty"`
	KeyFingerprint string `yaml:"key_fingerprint,omitempty" json:"key_fingerprint,omitempty"`
	Path           string `yaml:"path,omitempty" json:"path,omitempty"`
	PathPrefix     string `yaml:"path_prefix,omitempty" json:"path_prefix,omitempty"`
	PathGlob       string `yaml:"path_glob,omitempty" json:"path_glob,omitempty"`
	Filename       string `yaml:"filename,omitempty" json:"filename,omitempty"`
	FilenameGlob   string `yaml:"filename_glob,omitempty" json:"filename_glob,omitempty"`
}

func (s scopeConfig) match(operations ...string) matchConfig {
	return matchConfig{
		User:           s.User,
		KeyFingerprint: s.KeyFingerprint,
		Operation:      operations,
		Path:           s.Path,
		PathPrefix:     s.PathPrefix,
		PathGlob:       s.PathGlob,
		Filename:       s.Filename,
		FilenameGlob:   s.FilenameGlob,
	}
}

// failUploadConfig cuts off uploads after a number of bytes, then answers
// with a status, failure unless set, or closes or freezes the connection.
type failUploadConfig struct {
	scopeConfig `yaml:",inline"`
	Attempts    []uint64            `yaml:"attempts,flow,omitempty" json:"attempts,omitempty"`
	Probability *float64            `yaml:"probability,omitempty" json:"probability,omitempty"`
	AfterBytes  *valueRange[uint64] `yaml:"after_bytes,omitempty" json:"after_bytes,omitempty"`
	Result      string              `yaml:"result,omitempty" json:"result,omitempty"`
	Status      string              `yaml:"status,omitempty" json:"status,omitempty"`
	Mode        string              `yaml:"mode,omitempty" json:"mode,omitempty"`
	MaxFreeze   string              `yaml:"max_freeze,omitempty" json:"max_freeze,omitempty"`
}

// failRandomlyConfig fails a share of the requests of some operations
// before the server acts, with failure unless a status is set.
type failRandomlyConfig struct {
	scopeConfig `yaml:",inline"`
	Operations  stringList `yaml:"operations,omitempty" json:"operations,omitempty"`
	Probability *float64   `yaml:"probability,omitempty" json:"probability,omitempty"`
	Status      string     `yaml:"status,omitempty" json:"status,omitempty"`
	When        string     `yaml:"when,omitempty" json:"when,omitempty"`
}

// corruptDownloadConfig changes the bytes that downloads are served.
type corruptDownloadConfig struct {
	scopeConfig `yaml:",inline"`
	Attempts    []uint64 `yaml:"attempts,flow,omitempty" json:"attempts,omitempty"`
	Probability *float64 `yaml:"probability,omitempty" json:"probability,omitempty"`
	Transform   string   `yaml:"transform,omitempty" json:"transform,omitempty"`
	Offset      *uint64  `yaml:"offset,omitempty" json:"offset,omitempty"`
	Length      *uint64  `yaml:"length,omitempty" json:"length,omitempty"`
}

// expand returns rc with its recipe, if it has one, written in the long
// form, and the recipe's name.
func (rc ruleConfig) expand() (ruleConfig, string, error) {
	var recipes []string
	for name, set := range map[string]bool{
		"fail_upload":      rc.FailUpload != nil,
		"fail_randomly":    rc.FailRandomly != nil,
		"corrupt_download": rc.CorruptDownload != nil,
	} {
		if set {
			recipes = append(recipes, name)
		}
	}
	slices.Sort(recipes)
	switch len(recipes) {
	case 0:
		return rc, "", nil
	case 1:
	default:
		return rc, "", fmt.Errorf("%s and %s cannot both be set; a rule has one recipe at most", recipes[0], recipes[1])
	}
	recipe := recipes[0]
	if !reflect.ValueOf(rc.Match).IsZero() || rc.Decision != nil || !reflect.ValueOf(rc.Action).IsZero() {
		return rc, "", fmt.Errorf("a rule with the %s recipe has no match, decision or action", recipe)
	}
	var err error
	switch {
	case rc.FailUpload != nil:
		err = rc.FailUpload.expand(&rc)
	case rc.FailRandomly != nil:
		err = rc.FailRandomly.expand(&rc)
	case rc.CorruptDownload != nil:
		err = rc.CorruptDownload.expand(&rc)
	}
	if err != nil {
		return rc, "", fmt.Errorf("%s: %w", recipe, err)
	}
	return rc, recipe, nil
}

func (c failUploadConfig) expand(rc *ruleConfig) error {
	if c.AfterBytes == nil {
		return errors.New("after_bytes is required")
	}
	if c.AfterBytes.Min > c.AfterBytes.Max {
		return fmt.Errorf("the after_bytes range's min %d is above its max %d", c.AfterBytes.Min, c.AfterBytes.Max)
	}
	rc.Match = c.match("write")
	rc.Match.Attempt = attempts(c.Attempts)
	rc.Decision = decision(c.Probability)
	rc.Action = actionConfig{
		Type:         "partial_upload",
		CutoffOffset: c.AfterBytes,
		Result:       cmp.Or(c.Result, "status"),
		Status:       c.Status,
		Mode:         c.Mode,
		MaxFreeze:    c.MaxFreeze,
	}
	if rc.Action.Result == "status" {
		rc.Action.Status = cmp.Or(c.Status, "failure")
	}
	return nil
}

func (c failRandomlyConfig) expand(rc *ruleConfig) error {
	if len(c.Operations) == 0 {
		return errors.New("operations is required")
	}
	if c.Probability == nil {
		return errors.New("probability is required")
	}
	rc.Match = c.match(c.Operations...)
	rc.Decision = decision(c.Probability)
	rc.Action = actionConfig{Type: "fail", When: cmp.Or(c.When, "before"), Status: cmp.Or(c.Status, "failure")}
	return nil
}

func (c corruptDownloadConfig) expand(rc *ruleConfig) error {
	rc.Match = c.match("read")
	rc.Match.Attempt = attempts(c.Attempts)
	rc.Decision = decision(c.Probability)
	rc.Action = actionConfig{Type: "corrupt_download", Transform: c.Transform, Offset: c.Offset, Length: c.Length}
	return nil
}

// attempts returns the attempt of a recipe that lists numbers, counted per
// user and path.
func attempts(numbers []uint64) *attemptConfig {
	if numbers == nil {
		return nil
	}
	return &attemptConfig{Numbers: numbers}
}

// decision returns the decision of a recipe with a probability, if any.
func decision(probability *float64) *decisionConfig {
	if probability == nil {
		return nil
	}
	return &decisionConfig{Probability: probability}
}
