package faults_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

func TestRequestsAreNamedByOperation(t *testing.T) {
	tests := []struct {
		request sftpproxy.Request
		op      faults.Operation
	}{
		{openFor("/f", sftpwire.OpenRead), faults.OpenRead},
		{openFor("/f", sftpwire.OpenWrite|sftpwire.OpenCreate), faults.OpenWrite},
		{openFor("/f", sftpwire.OpenRead|sftpwire.OpenWrite), faults.OpenWrite},
		{openFor("/f", sftpwire.OpenCreate|sftpwire.OpenTruncate), faults.OpenRead},
		{on(&sftpwire.Read{}, "/f"), faults.Read},
		{on(&sftpwire.Write{}, "/f"), faults.Write},
		{on(&sftpwire.Close{}, "/f"), faults.Close},
		{on(&sftpwire.Stat{}, "/f"), faults.Stat},
		{on(&sftpwire.LStat{}, "/f"), faults.LStat},
		{on(&sftpwire.FStat{}, "/f"), faults.FStat},
		{on(&sftpwire.OpenDir{}, "/d"), faults.List},
		{on(&sftpwire.ReadDir{}, "/d"), faults.List},
		{on(&sftpwire.Mkdir{}, "/d"), faults.Mkdir},
		{on(&sftpwire.Rmdir{}, "/d"), faults.Rmdir},
		{on(&sftpwire.Remove{}, "/f"), faults.Remove},
		{on(&sftpwire.Rename{}, "/f"), faults.Rename},
		{on(&sftpwire.PosixRename{}, "/f"), faults.Rename},
		{on(&sftpwire.SetStat{}, "/f"), faults.SetStat},
		{on(&sftpwire.FSetStat{}, "/f"), faults.SetStat},
		{on(&sftpwire.RealPath{}, "/f"), faults.RealPath},
		{on(&sftpwire.StatVFS{}, "/f"), faults.StatVFS},
	}
	for _, tt := range tests {
		for _, op := range []faults.Operation{tt.op, faults.Any} {
			e := newEngine(t, failOn("r", faults.Match{Operations: ops(op)}))
			if got := session(e, "test", "")(tt.request); got != failure {
				t.Errorf("a rule for %s gave %#v for %T, want its fault", op, got, tt.request.Packet)
			}
		}
		e := newEngine(t, failOn("r", faults.Match{Operations: ops(faults.Mkdir)}))
		if tt.op != faults.Mkdir && session(e, "test", "")(tt.request) != nil {
			t.Errorf("a rule for mkdir matched %T", tt.request.Packet)
		}
	}
}

func TestLocationsMatchCanonicalPaths(t *testing.T) {
	tests := []struct {
		location faults.Location
		matches  []string
		misses   []string
	}{
		{faults.Location{}, []string{"/", "/a/b.csv", ""}, nil},
		{faults.Location{Kind: faults.Exactly, Pattern: "/in/a.csv"}, []string{"/in/a.csv"}, []string{"/in/a.csvx", "/in", "/IN/a.csv"}},
		{faults.Location{Kind: faults.Under, Pattern: "/in"}, []string{"/in", "/in/a.csv", "/in/sub/a.csv"}, []string{"/in-old/a.csv", "/", "/inx"}},
		{faults.Location{Kind: faults.Under, Pattern: "/"}, []string{"/", "/a", "/a/b"}, []string{""}},
		{faults.Location{Kind: faults.Glob, Pattern: "/in/*.csv"}, []string{"/in/a.csv", "/in/.csv"}, []string{"/in/sub/a.csv", "/in/a.CSV", "/out/a.csv"}},
		{faults.Location{Kind: faults.Named, Pattern: "orders.csv"}, []string{"/orders.csv", "/a/b/orders.csv"}, []string{"/orders.csv.part", "/Orders.csv", ""}},
		{faults.Location{Kind: faults.NamedGlob, Pattern: "*.part"}, []string{"/a.part", "/in/b.csv.part"}, []string{"/in/a.csv", "/a.part/b", ""}},
		{faults.Location{Kind: faults.NamedGlob, Pattern: "*"}, []string{"/a", "/in/.hidden"}, []string{""}},
	}
	for _, tt := range tests {
		e := newEngine(t, failOn("r", faults.Match{Operations: ops(faults.Stat), Path: tt.location}))
		decide := session(e, "test", "")
		for _, p := range tt.matches {
			if decide(on(&sftpwire.Stat{}, p)) == nil {
				t.Errorf("%+v did not match %q", tt.location, p)
			}
		}
		for _, p := range tt.misses {
			if decide(on(&sftpwire.Stat{}, p)) != nil {
				t.Errorf("%+v matched %q", tt.location, p)
			}
		}
	}
}

func TestRenamesMatchTheirSourceAndTarget(t *testing.T) {
	e := newEngine(t, failOn("publish", faults.Match{
		Operations: ops(faults.Rename),
		Path:       faults.Location{Kind: faults.NamedGlob, Pattern: "*.part"},
		Target:     faults.Location{Kind: faults.Exactly, Pattern: "/in/a.csv"},
	}))
	decide := session(e, "test", "")
	rename := func(from, to string) sftpproxy.Request {
		return sftpproxy.Request{Packet: &sftpwire.Rename{OldPath: from, NewPath: to}, Path: from, Target: to}
	}
	if decide(rename("/in/a.csv.part", "/in/a.csv")) == nil {
		t.Error("the rename was not matched")
	}
	if decide(rename("/in/a.csv.part", "/in/b.csv")) != nil || decide(rename("/in/a.tmp", "/in/a.csv")) != nil {
		t.Error("a rename with another source or target was matched")
	}
}

func TestCredentialsNarrowAMatch(t *testing.T) {
	e := newEngine(t, failOn("r", faults.Match{Operations: ops(faults.Stat), User: "partner-b", KeyFingerprint: "SHA256:abc"}))
	stat := on(&sftpwire.Stat{}, "/f")
	if session(e, "partner-b", "SHA256:abc")(stat) == nil {
		t.Error("the user's key was not matched")
	}
	for _, s := range []struct{ user, key string }{{"partner-b", ""}, {"partner-b", "SHA256:other"}, {"test", "SHA256:abc"}} {
		if session(e, s.user, s.key)(stat) != nil {
			t.Errorf("%q with key %q was matched", s.user, s.key)
		}
	}
}

func TestTheFirstRuleToSelectARequestWins(t *testing.T) {
	e := newEngine(t,
		faults.Rule{ID: "late", Priority: 20, Match: stat, Action: denied},
		faults.Rule{ID: "first", Priority: 10, Match: stat, Action: failure},
		faults.Rule{ID: "tied", Priority: 10, Match: stat, Action: denied},
	)
	if got := session(e, "test", "")(on(&sftpwire.Stat{}, "/f")); got != failure {
		t.Errorf("got %#v, want the lowest priority's fault, declared first among ties", got)
	}
	counts := e.Counts()
	for id, want := range map[string]faults.Counts{
		"first": {Matched: 1, Selected: 1, Fired: 1},
		"tied":  {Matched: 1},
		"late":  {Matched: 1},
	} {
		if counts[id] != want {
			t.Errorf("%s counts = %+v, want %+v", id, counts[id], want)
		}
	}
}

func TestOccurrencesCountEveryMatch(t *testing.T) {
	rename := faults.Match{Operations: ops(faults.Rename)}
	first, second := rename, rename
	first.Occurrence = []uint64{1}
	second.Occurrence = []uint64{2}
	e := newEngine(t,
		faults.Rule{ID: "first", Priority: 1, Match: first, Action: denied},
		faults.Rule{ID: "second", Priority: 2, Match: second, Action: failure},
	)
	decide := session(e, "test", "")
	// The second rule counts the first rename although the first rule
	// takes it.
	for i, want := range []sftpproxy.Action{denied, failure, nil} {
		if got := decide(on(&sftpwire.Rename{}, "/f")); got != want {
			t.Errorf("rename %d got %#v, want %#v", i+1, got, want)
		}
	}
}

func TestAttemptsCountOpensSeparately(t *testing.T) {
	const write = sftpwire.OpenWrite | sftpwire.OpenCreate
	tests := []struct {
		name    string
		attempt faults.Attempt
		// fails are whether each open, in order, fails.
		fails []bool
	}{
		{"per user and path", faults.Attempt{PerUser: true, PerPath: true, Numbers: []uint64{2}}, []bool{false, false, false, true, true, false}},
		{"per path", faults.Attempt{PerPath: true, Numbers: []uint64{2}}, []bool{false, false, true, false, true, false}},
		{"together", faults.Attempt{Numbers: []uint64{2, 3}}, []bool{false, true, true, false, false, false}},
	}
	opens := []struct{ user, path string }{
		{"a", "/x"}, {"a", "/y"}, {"b", "/x"}, {"a", "/x"}, {"a", "/y"}, {"b", "/y"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attempt := tt.attempt
			e := newEngine(t, failOn("r", faults.Match{Operations: ops(faults.OpenWrite), Attempt: &attempt}))
			for i, o := range opens {
				got := session(e, o.user, "")(openFor(o.path, write)) != nil
				if got != tt.fails[i] {
					t.Errorf("open %d (%s %s) failed: %v, want %v", i+1, o.user, o.path, got, tt.fails[i])
				}
			}
		})
	}
}

// TestAttemptsSelectUploadsByTheirOpen checks that a transfer rule that
// matches writes, with an attempt, chooses its fault at the open it counts,
// so that a retry of the upload goes through.
func TestAttemptsSelectUploadsByTheirOpen(t *testing.T) {
	const write = sftpwire.OpenWrite | sftpwire.OpenCreate
	first := &faults.Attempt{PerUser: true, PerPath: true, Numbers: []uint64{1}}
	e := newEngine(t, faults.Rule{ID: "cut", Match: faults.Match{Operations: ops(faults.Write), Attempt: first}, Action: cutOff})
	decide := session(e, "test", "")
	for i, o := range []struct {
		path string
		cut  bool
	}{{"/f", true}, {"/f", false}, {"/g", true}} {
		got := decide(openFor(o.path, write))
		if _, cut := got.(sftpproxy.PartialUpload); cut != o.cut {
			t.Errorf("open %d, of %s, got %#v; want a cutoff: %v", i+1, o.path, got, o.cut)
		}
	}
}

func TestMaxTriggersLeavesLaterRequestsToOtherRules(t *testing.T) {
	e := newEngine(t,
		faults.Rule{ID: "twice", Priority: 1, MaxTriggers: 2, Match: stat, Action: denied},
		faults.Rule{ID: "then", Priority: 2, Match: stat, Action: failure},
	)
	decide := session(e, "test", "")
	for i, want := range []sftpproxy.Action{denied, denied, failure} {
		if got := decide(on(&sftpwire.Stat{}, "/f")); got != want {
			t.Errorf("stat %d got %#v, want %#v", i+1, got, want)
		}
	}
	if got := e.Counts()["twice"]; got != (faults.Counts{Matched: 3, Selected: 2, Fired: 2}) {
		t.Errorf("counts = %+v", got)
	}
}

func TestTransfersAreSelectedAtOpenAndFireAtTheirEffect(t *testing.T) {
	var logs bytes.Buffer
	e, err := faults.New([]faults.Rule{{
		ID:          "cut",
		MaxTriggers: 1,
		Match:       faults.Match{Operations: ops(faults.Write), Path: faults.Location{Kind: faults.Exactly, Pattern: "/in/a.csv"}},
		Action:      cutOff,
	}}, nil, testSeed, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	decide := session(e, "test", "")
	if decide(on(&sftpwire.Write{}, "/in/a.csv")) != nil {
		t.Error("a write was given the transfer's fault, which belongs to the open")
	}
	if decide(openFor("/in/a.csv", sftpwire.OpenRead)) != nil {
		t.Error("an open for reading was given an upload's fault")
	}
	var reserves []func() bool
	for range 2 {
		a, ok := decide(openFor("/in/a.csv", sftpwire.OpenWrite)).(sftpproxy.PartialUpload)
		if !ok || a.Cutoff != cutOff.Cutoff || a.Reserve == nil {
			t.Fatalf("open for writing got %#v, want the rule's partial upload with a Reserve", a)
		}
		reserves = append(reserves, a.Reserve)
	}
	if got := e.Counts()["cut"]; got != (faults.Counts{Matched: 2, Selected: 2}) {
		t.Errorf("counts before either cutoff = %+v, want both selected and none fired", got)
	}
	if !reserves[1]() {
		t.Error("the first transfer to reach its cutoff was refused")
	}
	if reserves[0]() {
		t.Error("a second transfer took effect beyond max_triggers")
	}
	if got := e.Counts()["cut"]; got != (faults.Counts{Matched: 2, Selected: 2, Fired: 1}) {
		t.Errorf("counts = %+v, want one fired", got)
	}
	for _, want := range []string{
		`level=INFO msg="rule fired" rule=cut request=open_write path=/in/a.csv user=test ordinal=2`,
		`level=INFO msg="rule suppressed" rule=cut request=open_write path=/in/a.csv user=test ordinal=1 reason=max_triggers`,
	} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("logs lack %s:\n%s", want, logs.String())
		}
	}
}

func TestDownloadsAreSelectedAtTheirOpenForReading(t *testing.T) {
	corrupt := sftpproxy.CorruptDownload{Corruption: sftpproxy.FlipBytes, Offset: 0, Length: 64}
	e := newEngine(t, faults.Rule{ID: "flip", Match: faults.Match{Operations: ops(faults.Read)}, Action: corrupt})
	decide := session(e, "test", "")
	if decide(openFor("/f", sftpwire.OpenWrite)) != nil {
		t.Error("an open for writing was given a download's fault")
	}
	if a, ok := decide(openFor("/f", sftpwire.OpenRead)).(sftpproxy.CorruptDownload); !ok || a.Reserve == nil || a.Length != 64 {
		t.Errorf("open for reading got %#v, want the corruption with a Reserve", a)
	}
}

func TestWrongSizesApplyToListingEntries(t *testing.T) {
	shrink := sftpproxy.WrongSize{Delta: -1024}
	e := newEngine(t,
		faults.Rule{ID: "short", Priority: 1, Match: faults.Match{Operations: ops(faults.Stat, faults.List)}, Action: shrink},
		faults.Rule{ID: "slow", Priority: 2, Match: faults.Match{Operations: ops(faults.List)}, Action: sftpproxy.Delay{Duration: time.Second}},
	)
	decide := session(e, "test", "")
	entry := sftpproxy.Request{Packet: &sftpwire.ReadDir{}, Path: "/d/a.csv", Entry: true}
	if got := decide(entry); got != shrink {
		t.Errorf("a listing entry got %#v, want the wrong size", got)
	}
	if got := decide(on(&sftpwire.Stat{}, "/d/a.csv")); got != shrink {
		t.Errorf("a stat got %#v, want the wrong size", got)
	}
	if _, ok := decide(on(&sftpwire.ReadDir{}, "/d")).(sftpproxy.Delay); !ok {
		t.Error("a READDIR request did not get the listing's delay")
	}
	e = newEngine(t, faults.Rule{ID: "slow", Match: faults.Match{Operations: ops(faults.List)}, Action: sftpproxy.Delay{Duration: time.Second}})
	if session(e, "test", "")(entry) != nil {
		t.Error("a listing entry got a delay, which only applies to requests")
	}
}

func TestARandomRuleDrawsFromTheKeyOfEachRequest(t *testing.T) {
	const write = sftpwire.OpenWrite | sftpwire.OpenCreate
	opens := faults.Match{Operations: ops(faults.OpenWrite)}
	e := newEngine(t,
		faults.Rule{ID: "random", Priority: 1, Match: opens, Probability: new(0.5), Action: failure},
		faults.Rule{ID: "otherwise", Priority: 2, Match: opens, Action: denied},
	)
	// Each user's opens of each path count separately, so that no other
	// request changes a draw.
	ordinals := make(map[string]uint64)
	var fired, missed int
	for i := range 40 {
		user, path := []string{"a", "b"}[i%2], fmt.Sprintf("/in/%d.csv", i%3)
		ordinals[user+path]++
		draw := testSeed.Draw(faults.Key{Rule: "random", Choice: "probability", User: user, Path: path, Operation: "open_write", Ordinal: ordinals[user+path]})
		want := denied
		if draw.Fires(0.5) {
			want, fired = failure, fired+1
		} else {
			missed++
		}
		if got := session(e, user, "")(openFor(path, write)); got != want {
			t.Errorf("open %d (%s %s) got %#v, want %#v", i+1, user, path, got, want)
		}
	}
	if fired == 0 || missed == 0 {
		t.Fatalf("the rule fired %d times and missed %d; the test needs both", fired, missed)
	}
	counts := e.Counts()
	if want := (faults.Counts{Matched: 40, Selected: uint64(fired), Fired: uint64(fired)}); counts["random"] != want {
		t.Errorf("counts = %+v, want %+v", counts["random"], want)
	}
	if want := (faults.Counts{Matched: 40, Selected: uint64(missed), Fired: uint64(missed)}); counts["otherwise"] != want {
		t.Errorf("the next rule's counts = %+v, want %+v, as it takes each miss", counts["otherwise"], want)
	}
}

func TestProbabilitiesOfNoneAndAll(t *testing.T) {
	for _, p := range []float64{0, 1} {
		e := newEngine(t, faults.Rule{ID: "r", Match: stat, Probability: new(p), Action: failure})
		for range 20 {
			if got := session(e, "test", "")(on(&sftpwire.Stat{}, "/f")) != nil; got != (p == 1) {
				t.Fatalf("with probability %v, a stat got the fault: %v", p, got)
			}
		}
	}
}

func TestRangesDrawAValueForEachDecision(t *testing.T) {
	durations := faults.Range[time.Duration]{Min: time.Millisecond, Max: time.Second}
	cutoffs := faults.Range[uint64]{Min: 1 << 16, Max: 1 << 20}
	var logs bytes.Buffer
	e, err := faults.New([]faults.Rule{
		{ID: "slow", Match: faults.Match{Operations: ops(faults.Stat)}, Duration: &durations, Action: sftpproxy.Delay{When: sftpproxy.After}},
		{ID: "cut", Match: faults.Match{Operations: ops(faults.Write)}, Cutoff: &cutoffs, Action: cutOff},
	}, nil, testSeed, slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	if err != nil {
		t.Fatal(err)
	}
	decide := session(e, "test", "")
	seen := make(map[time.Duration]bool)
	for i := range uint64(20) {
		key := faults.Key{Rule: "slow", Choice: "duration", User: "test", Path: "/f", Operation: "stat", Ordinal: i + 1}
		want := sftpproxy.Delay{When: sftpproxy.After, Duration: faults.Between(testSeed.Draw(key), durations.Min, durations.Max)}
		if got := decide(on(&sftpwire.Stat{}, "/f")); unreleased(got) != want {
			t.Fatalf("stat %d got %#v, want %#v", i+1, got, want)
		}
		seen[want.Duration] = true
	}
	if len(seen) < 2 {
		t.Errorf("20 stats drew the durations %v; want them to vary", seen)
	}

	// A transfer draws its cutoff once, at its open.
	key := faults.Key{Rule: "cut", Choice: "cutoff", User: "test", Path: "/in/a.csv", Operation: "open_write", Ordinal: 1}
	want := faults.Between(testSeed.Draw(key), cutoffs.Min, cutoffs.Max)
	a, ok := decide(openFor("/in/a.csv", sftpwire.OpenWrite)).(sftpproxy.PartialUpload)
	if !ok || a.Cutoff != want || a.Result != cutOff.Result {
		t.Fatalf("the open got %#v, want the partial upload with cutoff %d", a, want)
	}
	if !a.Reserve() {
		t.Fatal("the transfer was refused its effect")
	}
	for _, line := range []string{
		fmt.Sprintf(`level=DEBUG msg=decision key.rule=cut key.activation=0 key.choice=cutoff key.user=test key.path=/in/a.csv key.operation=open_write key.ordinal=1 draw=%d min=65536 max=1048576 value=%d`, testSeed.Draw(key), want),
		fmt.Sprintf(`level=INFO msg="rule fired" rule=cut request=open_write path=/in/a.csv user=test ordinal=1 cutoff=%d`, want),
		`level=INFO msg="rule fired" rule=slow request=stat path=/f user=test ordinal=20 duration=`,
	} {
		if !strings.Contains(logs.String(), line) {
			t.Errorf("logs lack %s:\n%s", line, logs.String())
		}
	}
}

func TestEachOperationCountsItsOwnDraws(t *testing.T) {
	durations := faults.Range[time.Duration]{Min: time.Millisecond, Max: time.Second}
	e := newEngine(t, faults.Rule{ID: "slow", Match: faults.Match{Operations: ops(faults.Stat, faults.LStat)}, Duration: &durations, Action: sftpproxy.Delay{}})
	decide := session(e, "test", "")
	requests := []struct {
		packet  sftpwire.Packet
		op      string
		ordinal uint64
	}{
		{&sftpwire.Stat{}, "stat", 1},
		{&sftpwire.LStat{}, "lstat", 1},
		{&sftpwire.Stat{}, "stat", 2},
	}
	for _, r := range requests {
		key := faults.Key{Rule: "slow", Choice: "duration", User: "test", Path: "/f", Operation: r.op, Ordinal: r.ordinal}
		want := sftpproxy.Delay{Duration: faults.Between(testSeed.Draw(key), durations.Min, durations.Max)}
		if got := decide(on(r.packet, "/f")); unreleased(got) != want {
			t.Errorf("%s %d got %#v, want %#v", r.op, r.ordinal, got, want)
		}
	}
}

func TestARangeOfOneValueDrawsIt(t *testing.T) {
	e := newEngine(t, faults.Rule{ID: "cut", Match: faults.Match{Operations: ops(faults.Write)}, Cutoff: &faults.Range[uint64]{Min: 10, Max: 10}, Action: cutOff})
	if a, ok := session(e, "test", "")(openFor("/f", sftpwire.OpenWrite)).(sftpproxy.PartialUpload); !ok || a.Cutoff != 10 {
		t.Errorf("the open got %#v, want a cutoff of 10", a)
	}
}

func TestProbabilityDecisionsAreLogged(t *testing.T) {
	var logs bytes.Buffer
	e, err := faults.New([]faults.Rule{
		{ID: "random", Match: faults.Match{Operations: ops(faults.Remove)}, Probability: new(0.25), Action: failure},
	}, nil, testSeed, slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	if err != nil {
		t.Fatal(err)
	}
	session(e, "partner-b", "")(on(&sftpwire.Remove{}, "/out/a.csv"))
	key := faults.Key{Rule: "random", Choice: "probability", User: "partner-b", Path: "/out/a.csv", Operation: "remove", Ordinal: 1}
	draw := testSeed.Draw(key)
	line := fmt.Sprintf(`level=DEBUG msg=decision key.rule=random key.activation=0 key.choice=probability key.user=partner-b key.path=/out/a.csv key.operation=remove key.ordinal=1 draw=%d probability=0.25 fires=%v`, draw, draw.Fires(0.25))
	if !strings.Contains(logs.String(), line) {
		t.Errorf("logs lack %s:\n%s", line, logs.String())
	}
}

func TestRulesThatCannotApplyAreRefused(t *testing.T) {
	read := faults.Match{Operations: ops(faults.Read)}
	write := faults.Match{Operations: ops(faults.Write)}
	tests := []struct {
		name  string
		rules []faults.Rule
		err   string
	}{
		{"no ID", []faults.Rule{{Match: read, Action: failure}}, "a rule has no ID"},
		{"a repeated ID", []faults.Rule{failOn("r", read), failOn("r", read)}, `rule ID "r" is used twice`},
		{"an ID of chaos", []faults.Rule{failOn("chaos-delay", read)}, `rule ID "chaos-delay" starts with chaos-, which only the rules of a chaos preset have`},
		{"no operation", []faults.Rule{failOn("r", faults.Match{})}, "needs at least one operation"},
		{"an unknown operation", []faults.Rule{failOn("r", faults.Match{Operations: ops("upload")})}, `unknown operation "upload"`},
		{"a repeated operation", []faults.Rule{failOn("r", faults.Match{Operations: ops(faults.Read, faults.Read)})}, `operation "read" is listed twice`},
		{"a relative path", []faults.Rule{failOn("r", faults.Match{Operations: ops(faults.Read), Path: faults.Location{Kind: faults.Exactly, Pattern: "in/a"}})}, "not a clean absolute path"},
		{"an unclean prefix", []faults.Rule{failOn("r", faults.Match{Operations: ops(faults.Read), Path: faults.Location{Kind: faults.Under, Pattern: "/in/"}})}, "not a clean absolute path"},
		{"a ** glob", []faults.Rule{failOn("r", faults.Match{Operations: ops(faults.Read), Path: faults.Location{Kind: faults.Glob, Pattern: "/in/**"}})}, "uses **"},
		{"a bad glob", []faults.Rule{failOn("r", faults.Match{Operations: ops(faults.Read), Path: faults.Location{Kind: faults.Glob, Pattern: "/in/[a"}})}, "syntax error in pattern"},
		{"a name with a slash", []faults.Rule{failOn("r", faults.Match{Operations: ops(faults.Read), Path: faults.Location{Kind: faults.Named, Pattern: "in/a"}})}, "is not a file name"},
		{"a target off a rename", []faults.Rule{failOn("r", faults.Match{Operations: ops(faults.Remove), Target: faults.Location{Kind: faults.Exactly, Pattern: "/a"}})}, "match renames only"},
		{"a negative max_triggers", []faults.Rule{{ID: "r", MaxTriggers: -1, Match: read, Action: failure}}, "max_triggers is -1"},
		{"a cutoff off writes", []faults.Rule{{ID: "r", Match: read, Action: cutOff}}, "match the write operation only"},
		{"a cutoff that delays", []faults.Rule{{ID: "r", Match: faults.Match{Operations: ops(faults.Write)}, Action: sftpproxy.PartialUpload{Result: sftpproxy.Delay{}}}}, "cannot end with sftpproxy.Delay"},
		{"a corruption off reads", []faults.Rule{{ID: "r", Match: faults.Match{Operations: ops(faults.Read, faults.Stat)}, Action: sftpproxy.CorruptDownload{}}}, "match the read operation only"},
		{"a wrong size on a rename", []faults.Rule{{ID: "r", Match: faults.Match{Operations: ops(faults.Stat, faults.Rename)}, Action: sftpproxy.WrongSize{}}}, "not rename"},
		{"an action the engine makes itself", []faults.Rule{{ID: "r", Match: read, Action: sftpproxy.Timed{Action: sftpproxy.Drop{}}}}, "unsupported action sftpproxy.Timed"},
		{"attempts of renames", []faults.Rule{failOn("r", faults.Match{Operations: ops(faults.Rename), Attempt: &faults.Attempt{Numbers: []uint64{1}}})}, "attempts count opens"},
		{"attempts and occurrences", []faults.Rule{failOn("r", faults.Match{Operations: ops(faults.OpenRead), Attempt: &faults.Attempt{Numbers: []uint64{1}}, Occurrence: []uint64{1}})}, "cannot both be set"},
		{"no attempt numbers", []faults.Rule{failOn("r", faults.Match{Operations: ops(faults.OpenRead), Attempt: &faults.Attempt{}})}, "attempt needs at least one number"},
		{"occurrence 0", []faults.Rule{failOn("r", faults.Match{Operations: ops(faults.Rename), Occurrence: []uint64{0}})}, "count from 1"},
		{"a repeated occurrence", []faults.Rule{failOn("r", faults.Match{Operations: ops(faults.Rename), Occurrence: []uint64{2, 2}})}, "occurrence 2 is listed twice"},
		{"a negative probability", []faults.Rule{{ID: "r", Match: stat, Probability: new(-0.1), Action: failure}}, "probability -0.1 is not from 0 to 1"},
		{"a probability above 1", []faults.Rule{{ID: "r", Match: stat, Probability: new(1.5), Action: failure}}, "probability 1.5 is not from 0 to 1"},
		{"a probability that is not a number", []faults.Rule{{ID: "r", Match: stat, Probability: new(math.NaN()), Action: failure}}, "probability NaN is not from 0 to 1"},
		{"a duration range off a delay", []faults.Rule{{ID: "r", Match: stat, Duration: &faults.Range[time.Duration]{Min: 1, Max: 2}, Action: failure}}, "a duration range needs a delay"},
		{"a cutoff range off a partial upload", []faults.Rule{{ID: "r", Match: write, Cutoff: &faults.Range[uint64]{Min: 1, Max: 2}, Action: sftpproxy.Delay{}}}, "a cutoff range needs a partial upload"},
		{"an empty duration range", []faults.Rule{{ID: "r", Match: stat, Duration: &faults.Range[time.Duration]{Min: 3 * time.Second, Max: 200 * time.Millisecond}, Action: sftpproxy.Delay{}}}, "the duration range's min 3s is above its max 200ms"},
		{"an empty cutoff range", []faults.Rule{{ID: "r", Match: write, Cutoff: &faults.Range[uint64]{Min: 2, Max: 1}, Action: cutOff}}, "the cutoff_offset range's min 2 is above its max 1"},
		{"a trigger without an anchor", []faults.Rule{{ID: "r", Match: stat, Trigger: &faults.Trigger{At: at(time.Second)}, Action: failure}}, "a trigger needs an anchor"},
		{"a trigger with neither form", []faults.Rule{{ID: "r", Match: stat, Trigger: &faults.Trigger{Anchor: faults.Run}, Action: failure}}, "a trigger has either at or window"},
		{"a trigger with both forms", []faults.Rule{{ID: "r", Match: stat, Trigger: &faults.Trigger{Anchor: faults.Run, At: at(time.Second), Window: &faults.Window{Until: time.Second}}, Action: failure}}, "a trigger has either at or window"},
		{"a moment before its anchor", []faults.Rule{{ID: "r", Match: stat, Trigger: &faults.Trigger{Anchor: faults.Run, At: at(-time.Second)}, Action: failure}}, "at -1s is before its anchor"},
		{"an empty range of moments", []faults.Rule{{ID: "r", Match: stat, Trigger: &faults.Trigger{Anchor: faults.Run, At: &faults.Range[time.Duration]{Min: 2, Max: 1}}, Action: failure}}, "the at range's min 2ns is above its max 1ns"},
		{"an empty window", []faults.Rule{{ID: "r", Match: stat, Trigger: &faults.Trigger{Anchor: faults.Run, Window: &faults.Window{From: time.Second, Until: time.Second}}, Action: failure}}, "the window from 1s until 1s is empty"},
		{"a window before its anchor", []faults.Rule{{ID: "r", Match: stat, Trigger: &faults.Trigger{Anchor: faults.Run, Window: &faults.Window{From: -time.Second, Until: time.Second}}, Action: failure}}, "starts before its anchor"},
		{"a transfer's moment for a failure", []faults.Rule{{ID: "r", Match: write, Trigger: &faults.Trigger{Anchor: faults.Transfer, At: at(time.Second)}, Action: failure}}, "a transfer anchor needs at and a connection action"},
		{"a transfer's window", []faults.Rule{{ID: "r", Match: write, Trigger: &faults.Trigger{Anchor: faults.Transfer, Window: &faults.Window{Until: time.Second}}, Action: sftpproxy.Drop{}}}, "a transfer anchor needs at and a connection action"},
		{"a transfer's moment off transfers", []faults.Rule{{ID: "r", Match: stat, Trigger: &faults.Trigger{Anchor: faults.Transfer, At: at(time.Second)}, Action: sftpproxy.Drop{}}}, "a transfer anchor needs transfer operations, open_read, open_write, read and write, not stat"},
		{"a run's moment for operations", []faults.Rule{{ID: "r", Match: stat, Trigger: &faults.Trigger{Anchor: faults.Run, At: at(time.Second)}, Action: sftpproxy.Drop{}}}, "a connection action at a moment of the run matches only the user and key"},
		{"a connection's moment for a path", []faults.Rule{{ID: "r", Match: faults.Match{Path: faults.Location{Kind: faults.Exactly, Pattern: "/a"}}, Trigger: &faults.Trigger{Anchor: faults.Connection, At: at(time.Second)}, Action: sftpproxy.EndSession{}}}, "a connection action at a moment of the connection matches only the user and key"},
		{"a connection's moment by chance", []faults.Rule{{ID: "r", Probability: new(0.5), Trigger: &faults.Trigger{Anchor: faults.Connection, At: at(time.Second)}, Action: sftpproxy.Drop{}}}, "a connection action at a moment of the connection takes no probability"},
		{"no operation for a request", []faults.Rule{{ID: "r", Trigger: &faults.Trigger{Anchor: faults.Run, Window: &faults.Window{Until: time.Second}}, Action: sftpproxy.Drop{}}}, "needs at least one operation"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := faults.New(tt.rules, nil, testSeed, nil)
			if err == nil || !strings.Contains(err.Error(), tt.err) || !strings.HasPrefix(err.Error(), "faults: ") {
				t.Errorf("New = %v, want an error about %q", err, tt.err)
			}
		})
	}
}
