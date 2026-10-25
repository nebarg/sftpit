package faults_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

// betweenTransfers are the operations that chaos fails and freezes: all but
// read and write.
var betweenTransfers = ops(faults.OpenRead, faults.OpenWrite, faults.Close, faults.Stat, faults.LStat, faults.FStat, faults.List, faults.Mkdir, faults.Rmdir, faults.Remove, faults.Rename, faults.SetStat, faults.RealPath, faults.StatVFS)

func TestEachPresetCompilesToItsDocumentedRules(t *testing.T) {
	delay := func(p float64) faults.Rule {
		return faults.Rule{ID: "chaos-delay", Match: faults.Match{Operations: ops(faults.Any)}, Probability: new(p), Duration: &faults.Range[time.Duration]{Min: 200 * time.Millisecond, Max: 2 * time.Second}, Action: sftpproxy.Delay{When: sftpproxy.Before}}
	}
	fail := func(p float64) faults.Rule {
		return faults.Rule{ID: "chaos-fail", Match: faults.Match{Operations: betweenTransfers}, Probability: new(p), Action: failure}
	}
	drop := func(p float64) faults.Rule {
		return faults.Rule{ID: "chaos-drop", Match: faults.Match{Operations: ops(faults.Read, faults.Write)}, Trigger: &faults.Trigger{Anchor: faults.Transfer, At: &faults.Range[time.Duration]{Max: time.Second}}, Probability: new(p), Action: sftpproxy.Drop{}}
	}
	freeze := faults.Rule{ID: "chaos-freeze", Match: faults.Match{Operations: betweenTransfers}, Probability: new(0.005), Action: sftpproxy.Freeze{When: sftpproxy.Before, Limit: 15 * time.Second}}
	tests := []struct {
		preset faults.Preset
		want   []faults.Rule
	}{
		{faults.Light, []faults.Rule{delay(0.05), fail(0.01)}},
		{faults.Moderate, []faults.Rule{delay(0.10), fail(0.03), drop(0.02)}},
		{faults.Heavy, []faults.Rule{delay(0.20), fail(0.08), drop(0.05), freeze}},
	}
	for _, tt := range tests {
		if got := (faults.Chaos{Preset: tt.preset}).Rules(); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s compiles to %s, want %s", tt.preset, describe(got), describe(tt.want))
		}
	}
}

func TestChaosAddsItsExtrasOverItsScope(t *testing.T) {
	scope := faults.Scope{User: "partner-b", KeyFingerprint: "SHA256:key", Path: faults.Location{Kind: faults.Under, Pattern: "/incoming"}}
	in := func(m faults.Match) faults.Match {
		m.User, m.KeyFingerprint, m.Path = scope.User, scope.KeyFingerprint, scope.Path
		return m
	}
	extras := []faults.Rule{
		{ID: "chaos-corrupt-download", Match: in(faults.Match{Operations: ops(faults.Read)}), Probability: new(0.03), Action: sftpproxy.CorruptDownload{Corruption: sftpproxy.FlipBytes, Length: 64}},
		{ID: "chaos-wrong-size", Match: in(faults.Match{Operations: ops(faults.Stat, faults.LStat, faults.FStat, faults.List)}), Probability: new(0.03), Action: sftpproxy.WrongSize{Delta: -1024}},
	}
	// The extras come in the same order however they are listed, so that
	// listing them in another order changes no rule.
	for _, listed := range [][]faults.Extra{{faults.CorruptDownloads, faults.WrongSizes}, {faults.WrongSizes, faults.CorruptDownloads}} {
		got := (faults.Chaos{Preset: faults.Moderate, Scope: scope, Extras: listed}).Rules()
		var want []faults.Rule
		for _, r := range (faults.Chaos{Preset: faults.Moderate}).Rules() {
			r.Match = in(r.Match)
			want = append(want, r)
		}
		if want = append(want, extras...); !reflect.DeepEqual(got, want) {
			t.Errorf("moderate chaos with %v compiles to %s, want %s", listed, describe(got), describe(want))
		}
	}
	if got := (faults.Chaos{Preset: faults.Light, Extras: []faults.Extra{faults.WrongSizes}}).Rules(); len(got) != 3 || got[2].ID != "chaos-wrong-size" {
		t.Errorf("light chaos with wrong_size compiles to %s, want its two rules and chaos-wrong-size", describe(got))
	}
}

func TestNoPresetCorruptsUnlessAskedTo(t *testing.T) {
	for _, preset := range []faults.Preset{faults.Light, faults.Moderate, faults.Heavy} {
		for _, r := range (faults.Chaos{Preset: preset}).Rules() {
			switch r.Action.(type) {
			case sftpproxy.CorruptDownload, sftpproxy.WrongSize:
				t.Errorf("%s chaos has %s, a %T, without the extra", preset, r.ID, r.Action)
			}
		}
	}
}

func TestTheRulesOfChaosAreValid(t *testing.T) {
	for _, preset := range []faults.Preset{faults.Light, faults.Moderate, faults.Heavy} {
		c := faults.Chaos{Preset: preset, Scope: faults.Scope{User: "test", Path: faults.Location{Kind: faults.Named, Pattern: "orders.csv"}}, Extras: []faults.Extra{faults.CorruptDownloads, faults.WrongSizes}}
		rules := c.Rules()
		// Only chaos's own rules may have IDs that start with chaos-.
		for i := range rules {
			rules[i].ID = strings.TrimPrefix(rules[i].ID, "chaos-")
		}
		if err := faults.Check(rules); err != nil {
			t.Errorf("the rules of %s chaos are refused: %v", preset, err)
		}
	}
}

func TestChaosThatCannotApplyIsRefused(t *testing.T) {
	tests := []struct {
		name  string
		chaos faults.Chaos
		err   string
	}{
		{"no preset", faults.Chaos{}, "chaos needs a preset: light, moderate or heavy"},
		{"an unknown preset", faults.Chaos{Preset: "wild"}, `chaos preset "wild" is not light, moderate or heavy`},
		{"an unknown extra", faults.Chaos{Preset: faults.Light, Extras: []faults.Extra{"corrupt_upload"}}, `chaos extra "corrupt_upload" is not corrupt_download or wrong_size`},
		{"an extra listed twice", faults.Chaos{Preset: faults.Light, Extras: []faults.Extra{faults.CorruptDownloads, faults.WrongSizes, faults.WrongSizes}}, `chaos extra "wrong_size" is listed twice`},
		{"an unclean scope", faults.Chaos{Preset: faults.Light, Scope: faults.Scope{Path: faults.Location{Kind: faults.Under, Pattern: "/in/"}}}, `chaos scope: path: "/in/" is not a clean absolute path`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := faults.New(nil, &tt.chaos, testSeed, nil); err == nil || !strings.HasPrefix(err.Error(), "faults: "+tt.err) {
				t.Errorf("New = %v, want an error about %q", err, tt.err)
			}
			e := newEngine(t)
			if _, err := e.Replace(1, nil, &tt.chaos); err == nil || !strings.Contains(err.Error(), tt.err) {
				t.Errorf("Replace = %v, want an error about %q", err, tt.err)
			}
			if set := e.Rules(); set.Revision != 1 || set.Chaos != nil {
				t.Errorf("after a refused change, the rules are %+v, want revision 1 without chaos", set)
			}
		})
	}
}

func TestChaosIsTriedAfterTheScenariosOwnRules(t *testing.T) {
	last := faults.Rule{ID: "last", Priority: 9, Match: stat, Action: denied}
	chaos := &faults.Chaos{Preset: faults.Heavy}
	e, err := faults.New([]faults.Rule{last}, chaos, testSeed, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	decide := session(e, "test", "")
	for i := range 100 {
		if got := decide(on(&sftpwire.Stat{}, "/f")); got != denied {
			t.Fatalf("stat %d got %#v, want the scenario's own rule, however low its priority", i+1, got)
		}
	}
	set := e.Rules()
	if len(set.Rules) != 1 || set.Rules[0].ID != "last" || set.Chaos != chaos {
		t.Errorf("the rules are %+v with chaos %+v, want the scenario's own and the chaos apart", set.Rules, set.Chaos)
	}
	want := map[string]faults.Counts{
		"last":         {Matched: 100, Selected: 100, Fired: 100},
		"chaos-delay":  {Matched: 100},
		"chaos-fail":   {Matched: 100},
		"chaos-drop":   {},
		"chaos-freeze": {Matched: 100},
	}
	if !reflect.DeepEqual(set.Counts, want) {
		t.Errorf("counts = %+v, want %+v", set.Counts, want)
	}
}

func TestPausedChaosMatchesNothingAndKeepsItsCounts(t *testing.T) {
	var logs bytes.Buffer
	deny := faults.Rule{ID: "deny-lstat", Match: faults.Match{Operations: ops(faults.LStat)}, Action: denied}
	// Chaos is scoped to /f, so that the lstats of /g show the scenario's
	// own rule going on.
	f := faults.Scope{Path: faults.Location{Kind: faults.Exactly, Pattern: "/f"}}
	paused := &faults.Chaos{Preset: faults.Light, Scope: f, Paused: true}
	running := &faults.Chaos{Preset: faults.Light, Scope: f}
	// The run starts without chaos, so that a change adds it.
	e, err := faults.New([]faults.Rule{deny}, nil, testSeed, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	decide := session(e, "test", "")
	steps := []struct {
		chaos *faults.Chaos
		stats int
		// matched is how many stats chaos has matched after the step.
		matched uint64
	}{
		{paused, 3, 0},
		{running, 3, 3},
		{paused, 3, 3},
		{running, 2, 5},
	}
	for i, step := range steps {
		if _, err := e.Replace(e.Revision(), []faults.Rule{deny}, step.chaos); err != nil {
			t.Fatal(err)
		}
		for range step.stats {
			decide(on(&sftpwire.Stat{}, "/f"))
		}
		if got := decide(on(&sftpwire.LStat{}, "/g")); got != denied {
			t.Errorf("step %d: an lstat got %#v, want the scenario's own rule whatever chaos does", i+1, got)
		}
		counts := e.Counts()
		if got := counts["chaos-delay"].Matched; got != step.matched || counts["chaos-fail"].Matched != got {
			t.Errorf("step %d: chaos matched %+v, want %d stats", i+1, counts, step.matched)
		}
	}
	if want := `msg="rules changed" from=3 to=4 added=[] changed=[] removed=[] kept="[deny-lstat chaos-delay chaos-fail]" chaos=light chaos_paused=true`; !strings.Contains(logs.String(), want) {
		t.Errorf("logs lack %s:\n%s", want, logs.String())
	}
}

func TestAMomentThatChaosChoseDoesNotComeWhilePaused(t *testing.T) {
	var logs bytes.Buffer
	heavy := &faults.Chaos{Preset: faults.Heavy}
	e, err := faults.New(nil, heavy, testSeed, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	decide := session(e, "test", "")
	var drop sftpproxy.Timed
	for i := 1; ; i++ {
		var ok bool
		if drop, ok = decide(openFor(fmt.Sprintf("/f%d", i), sftpwire.OpenWrite)).(sftpproxy.Timed); ok {
			break
		}
		if i == 1000 {
			t.Fatal("chaos chose none of 1000 uploads for a drop")
		}
	}
	if _, err := e.Replace(1, nil, &faults.Chaos{Preset: faults.Heavy, Paused: true}); err != nil {
		t.Fatal(err)
	}
	if drop.Reserve() {
		t.Error("a drop came while chaos was paused")
	}
	if !strings.Contains(logs.String(), `msg="rule suppressed" rule=chaos-drop`) || !strings.Contains(logs.String(), "reason=paused") {
		t.Errorf("logs lack the suppressed drop:\n%s", logs.String())
	}
	if _, err := e.Replace(2, nil, heavy); err != nil {
		t.Fatal(err)
	}
	if !drop.Reserve() {
		t.Error("a drop whose moment came after chaos resumed did not come")
	}
}

// describe returns rules as text that shows the values behind their
// pointers.
func describe(rules []faults.Rule) string {
	var b strings.Builder
	for _, r := range rules {
		fmt.Fprintf(&b, "\n  %s: %+v", r.ID, r.Match)
		if r.Probability != nil {
			fmt.Fprintf(&b, " probability %v", *r.Probability)
		}
		if r.Duration != nil {
			fmt.Fprintf(&b, " duration %+v", *r.Duration)
		}
		if r.Trigger != nil {
			fmt.Fprintf(&b, " trigger %v at %+v", r.Trigger.Anchor, r.Trigger.At)
		}
		fmt.Fprintf(&b, " %#v", r.Action)
	}
	return b.String()
}
