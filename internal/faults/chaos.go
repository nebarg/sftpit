package faults

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

// Chaos is a preset of random delays, failures and drops over a scope, for
// trying a live system against unpredictable trouble. An engine applies it
// as the ordinary rules that Rules returns, after the scenario's own.
type Chaos struct {
	Preset Preset

	// Scope narrows the requests that chaos applies to.
	Scope Scope

	// Extras are faults that no preset makes, since silently corrupted data
	// would surprise in a long session.
	Extras []Extra

	// Paused keeps the rules of chaos but stops them choosing faults: they
	// match no request, and a moment they chose does not come. A delay or
	// freeze under way, or a download chosen for corruption, goes on.
	Paused bool
}

// Preset is how much trouble chaos makes.
type Preset string

const (
	// Light delays 5% of requests and fails 1% of operations.
	Light Preset = "light"

	// Moderate delays 10% of requests, fails 3% of operations and drops the
	// connection during 2% of transfers.
	Moderate Preset = "moderate"

	// Heavy delays 20% of requests, fails 8% of operations, drops the
	// connection during 5% of transfers and freezes it at 0.5% of
	// operations.
	Heavy Preset = "heavy"
)

// chances are a preset's chances that a request is delayed, that an
// operation fails or freezes the connection, and that a transfer is
// dropped. A chance of 0 leaves out its rule.
type chances struct{ delay, fail, drop, freeze float64 }

var presets = map[Preset]chances{
	Light:    {delay: 0.05, fail: 0.01},
	Moderate: {delay: 0.10, fail: 0.03, drop: 0.02},
	Heavy:    {delay: 0.20, fail: 0.08, drop: 0.05, freeze: 0.005},
}

// Extra is a fault that chaos makes only when asked to.
type Extra string

const (
	// CorruptDownloads changes the first 64 bytes served of a share of
	// downloads, as many as the preset fails operations.
	CorruptDownloads Extra = "corrupt_download"

	// WrongSizes reports sizes 1 KiB short in as many stat replies and
	// listings as the preset fails operations.
	WrongSizes Extra = "wrong_size"
)

// Scope is the clients and paths that chaos applies to. A field left empty
// matches every request.
type Scope struct {
	User           string
	KeyFingerprint string
	Path           Location
}

// chaosPrefix starts the ID of every rule of chaos, and of no other.
const chaosPrefix = "chaos-"

// Rules returns the rules that c applies, in the order they are tried:
//   - chaos-delay delays a request by 200 ms to 2 s before the server acts;
//   - chaos-fail answers an operation with failure before the server acts;
//   - chaos-drop closes the connection at a moment up to 1 s after a
//     transfer's file opens, if it is still open then;
//   - chaos-freeze freezes the connection before an operation, for up to
//     15 s;
//   - chaos-corrupt-download and chaos-wrong-size make the extras.
//
// Every request draws for a delay, reads and writes included, as on a slow
// link. Only the other operations draw for a failure or a freeze, so that a
// transfer is decided at its open and close, and its chance of failing does
// not grow with its size; the drops make trouble during a transfer.
func (c Chaos) Rules() []Rule {
	p := presets[c.Preset]
	match := func(ops ...Operation) Match {
		return Match{User: c.Scope.User, KeyFingerprint: c.Scope.KeyFingerprint, Operations: ops, Path: c.Scope.Path}
	}
	between := slices.DeleteFunc(slices.Clone(operations), func(op Operation) bool { return op == Read || op == Write })
	rules := []Rule{
		{ID: "chaos-delay", Match: match(Any), Probability: new(p.delay), Duration: &Range[time.Duration]{Min: 200 * time.Millisecond, Max: 2 * time.Second}, Action: sftpproxy.Delay{When: sftpproxy.Before}},
		{ID: "chaos-fail", Match: match(between...), Probability: new(p.fail), Action: sftpproxy.Fail{When: sftpproxy.Before, Status: sftpwire.StatusFailure}},
	}
	if p.drop > 0 {
		rules = append(rules, Rule{ID: "chaos-drop", Match: match(Read, Write), Trigger: &Trigger{Anchor: Transfer, At: &Range[time.Duration]{Max: time.Second}}, Probability: new(p.drop), Action: sftpproxy.Drop{}})
	}
	if p.freeze > 0 {
		rules = append(rules, Rule{ID: "chaos-freeze", Match: match(between...), Probability: new(p.freeze), Action: sftpproxy.Freeze{When: sftpproxy.Before, Limit: 15 * time.Second}})
	}
	if slices.Contains(c.Extras, CorruptDownloads) {
		rules = append(rules, Rule{ID: "chaos-corrupt-download", Match: match(Read), Probability: new(p.fail), Action: sftpproxy.CorruptDownload{Corruption: sftpproxy.FlipBytes, Length: 64}})
	}
	if slices.Contains(c.Extras, WrongSizes) {
		rules = append(rules, Rule{ID: "chaos-wrong-size", Match: match(Stat, LStat, FStat, List), Probability: new(p.fail), Action: sftpproxy.WrongSize{Delta: -1024}})
	}
	return rules
}

// Check reports a chaos that an engine cannot apply.
func (c Chaos) Check() error {
	switch _, ok := presets[c.Preset]; {
	case c.Preset == "":
		return errors.New("faults: chaos needs a preset: light, moderate or heavy")
	case !ok:
		return fmt.Errorf("faults: chaos preset %q is not light, moderate or heavy", c.Preset)
	}
	for i, x := range c.Extras {
		if x != CorruptDownloads && x != WrongSizes {
			return fmt.Errorf("faults: chaos extra %q is not corrupt_download or wrong_size", x)
		}
		if slices.Contains(c.Extras[:i], x) {
			return fmt.Errorf("faults: chaos extra %q is listed twice", x)
		}
	}
	if err := c.Scope.Path.check(); err != nil {
		return fmt.Errorf("faults: chaos scope: path: %w", err)
	}
	return nil
}
