package faults_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

var (
	failure = sftpproxy.Fail{When: sftpproxy.Before, Status: sftpwire.StatusFailure}
	denied  = sftpproxy.Fail{When: sftpproxy.Before, Status: sftpwire.StatusPermissionDenied}
	cutOff  = sftpproxy.PartialUpload{Cutoff: 1 << 20, Result: failure}
)

func openFor(path string, flags uint32) sftpproxy.Request {
	return sftpproxy.Request{Packet: &sftpwire.Open{Path: path, Flags: flags}, Path: path}
}

func on(p sftpwire.Packet, path string) sftpproxy.Request {
	return sftpproxy.Request{Packet: p, Path: path}
}

func newEngine(t *testing.T, rules ...faults.Rule) *faults.Engine {
	t.Helper()
	e, err := faults.New(rules, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

func failOn(id string, m faults.Match) faults.Rule {
	return faults.Rule{ID: id, Match: m, Action: failure}
}

func ops(o ...faults.Operation) []faults.Operation { return o }

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
			if got := e.Session("test", "")(tt.request); got != failure {
				t.Errorf("a rule for %s gave %#v for %T, want its fault", op, got, tt.request.Packet)
			}
		}
		e := newEngine(t, failOn("r", faults.Match{Operations: ops(faults.Mkdir)}))
		if tt.op != faults.Mkdir && e.Session("test", "")(tt.request) != nil {
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
		decide := e.Session("test", "")
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
	decide := e.Session("test", "")
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
	if e.Session("partner-b", "SHA256:abc")(stat) == nil {
		t.Error("the user's key was not matched")
	}
	for _, s := range []struct{ user, key string }{{"partner-b", ""}, {"partner-b", "SHA256:other"}, {"test", "SHA256:abc"}} {
		if e.Session(s.user, s.key)(stat) != nil {
			t.Errorf("%q with key %q was matched", s.user, s.key)
		}
	}
}

func TestTheFirstRuleToSelectARequestWins(t *testing.T) {
	stat := faults.Match{Operations: ops(faults.Stat)}
	e := newEngine(t,
		faults.Rule{ID: "late", Priority: 20, Match: stat, Action: denied},
		faults.Rule{ID: "first", Priority: 10, Match: stat, Action: failure},
		faults.Rule{ID: "tied", Priority: 10, Match: stat, Action: denied},
	)
	if got := e.Session("test", "")(on(&sftpwire.Stat{}, "/f")); got != failure {
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
	decide := e.Session("test", "")
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
				got := e.Session(o.user, "")(openFor(o.path, write)) != nil
				if got != tt.fails[i] {
					t.Errorf("open %d (%s %s) failed: %v, want %v", i+1, o.user, o.path, got, tt.fails[i])
				}
			}
		})
	}
}

func TestMaxTriggersLeavesLaterRequestsToOtherRules(t *testing.T) {
	stat := faults.Match{Operations: ops(faults.Stat)}
	e := newEngine(t,
		faults.Rule{ID: "twice", Priority: 1, MaxTriggers: 2, Match: stat, Action: denied},
		faults.Rule{ID: "then", Priority: 2, Match: stat, Action: failure},
	)
	decide := e.Session("test", "")
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
	}}, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	decide := e.Session("test", "")
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
	decide := e.Session("test", "")
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
	decide := e.Session("test", "")
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
	if e.Session("test", "")(entry) != nil {
		t.Error("a listing entry got a delay, which only applies to requests")
	}
}

func TestRulesThatCannotApplyAreRefused(t *testing.T) {
	read := faults.Match{Operations: ops(faults.Read)}
	tests := []struct {
		name  string
		rules []faults.Rule
		err   string
	}{
		{"no ID", []faults.Rule{{Match: read, Action: failure}}, "a rule has no ID"},
		{"a repeated ID", []faults.Rule{failOn("r", read), failOn("r", read)}, `rule ID "r" is used twice`},
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
		{"a stall", []faults.Rule{{ID: "r", Match: read, Action: sftpproxy.Stall{}}}, "unsupported action sftpproxy.Stall"},
		{"attempts of renames", []faults.Rule{failOn("r", faults.Match{Operations: ops(faults.Rename), Attempt: &faults.Attempt{Numbers: []uint64{1}}})}, "attempts count opens"},
		{"attempts and occurrences", []faults.Rule{failOn("r", faults.Match{Operations: ops(faults.OpenRead), Attempt: &faults.Attempt{Numbers: []uint64{1}}, Occurrence: []uint64{1}})}, "cannot both be set"},
		{"no attempt numbers", []faults.Rule{failOn("r", faults.Match{Operations: ops(faults.OpenRead), Attempt: &faults.Attempt{}})}, "attempt needs at least one number"},
		{"occurrence 0", []faults.Rule{failOn("r", faults.Match{Operations: ops(faults.Rename), Occurrence: []uint64{0}})}, "count from 1"},
		{"a repeated occurrence", []faults.Rule{failOn("r", faults.Match{Operations: ops(faults.Rename), Occurrence: []uint64{2, 2}})}, "occurrence 2 is listed twice"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := faults.New(tt.rules, nil)
			if err == nil || !strings.Contains(err.Error(), tt.err) || !strings.HasPrefix(err.Error(), "faults: ") {
				t.Errorf("New = %v, want an error about %q", err, tt.err)
			}
		})
	}
}
