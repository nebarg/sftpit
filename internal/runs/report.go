package runs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strconv"
	"time"

	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/events"
	"github.com/nebarg/sftpit/internal/faults"
)

// reportFile holds a run's report, in its directory.
const reportFile = "report.json"

// reportVersion is the format of a report.
const reportVersion = 1

// Report is the verdict on a run, and the evidence for it. A run passes only
// if it states assertions, every one holds and no transfer was unfinished.
// It says what the server saw, not whether the application recovered, which
// is for the application's own tests.
type Report struct {
	SchemaVersion int       `json:"schema_version"`
	Run           ReportRun `json:"run"`
	Passed        bool      `json:"passed"`

	// Problems say why the run failed apart from its assertions.
	Problems   []string          `json:"problems,omitempty"`
	Assertions []AssertionResult `json:"assertions"`

	// Unfinished are the paths of the files whose handles were still open
	// when the drain ended their connections.
	Unfinished []string `json:"unfinished,omitempty"`

	// Interactive is set if the run's rules changed while it ran, so that
	// a run of its scenario would not repeat it.
	Interactive bool `json:"interactive,omitempty"`

	// Rules are what each rule of the run did, by ID, those of its chaos
	// included.
	Rules map[string]RuleResult `json:"rules"`

	Trace     TraceResult `json:"trace"`
	Files     []FinalFile `json:"files"`
	Snapshots int         `json:"snapshots"`
}

// ReportRun describes the run a report is about. Seed is a decimal string,
// as the control API writes seeds.
type ReportRun struct {
	ID         string    `json:"id"`
	Started    time.Time `json:"started"`
	Scenario   string    `json:"scenario,omitempty"`
	Inline     bool      `json:"inline,omitempty"`
	Seed       string    `json:"seed"`
	SeedPinned bool      `json:"seed_pinned,omitempty"`
}

// AssertionResult is the verdict on one assertion: Assertion as a scenario
// gives it, Description in a line, and Detail saying what was found.
type AssertionResult struct {
	Assertion   json.RawMessage `json:"assertion"`
	Description string          `json:"description"`
	Passed      bool            `json:"passed"`
	Detail      string          `json:"detail"`
}

// RuleResult is what a rule did in a run, as faults.Counts.
type RuleResult struct {
	Matched  uint64 `json:"matched"`
	Selected uint64 `json:"selected"`
	Fired    uint64 `json:"fired"`
}

// TraceResult describes a run's trace, as events.TraceStatus.
type TraceResult struct {
	Bytes    int64  `json:"bytes"`
	Complete bool   `json:"complete"`
	Error    string `json:"error,omitempty"`
}

// FinalFile describes a file as the run left it.
type FinalFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Assert drains run, which must be the current run, as Drain does, waiting
// for up to wait, then gives the verdict on it and keeps the report in its
// directory, which OpenReport reads. A run that fails is not an error; an
// error means that there is no verdict. Asserting again gives the same
// report, since nothing can have changed.
func (m *Manager) Assert(ctx context.Context, run string, wait time.Duration) (Report, error) {
	m.resetting.Lock()
	defer m.resetting.Unlock()
	current, err := m.drainable(run)
	if err != nil {
		return Report{}, err
	}
	m.mu.Lock()
	report := current.report
	m.mu.Unlock()
	if report != nil {
		return *report, nil
	}
	drained, err := m.drain(ctx, current, wait)
	if err != nil {
		return Report{}, err
	}
	r, err := m.evaluate(current, drained)
	if err != nil {
		return Report{}, err
	}
	if err := m.workspace.writeReport(run, r); err != nil {
		return Report{}, err
	}
	m.mu.Lock()
	current.report = &r
	m.mu.Unlock()
	m.logger.Info("run asserted", "run", run, "passed", r.Passed)
	return r, nil
}

// OpenReport opens the report of run, one of the runs the workspace keeps,
// for reading. A run the workspace does not keep fails with ErrUnknownRun,
// and one not asserted with an error wrapping fs.ErrNotExist.
func (m *Manager) OpenReport(run string) (*os.File, error) {
	dir, err := m.workspace.openRun(run, ".")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	f, err := dir.Open(reportFile)
	if err != nil {
		return nil, fmt.Errorf("runs: open the report: %w", err)
	}
	return f, nil
}

// writeReport writes r to the run id's directory, through a temporary file
// renamed over the name, so that a reader never sees part of it.
func (w *Workspace) writeReport(id string, r Report) error {
	name := path.Join(runsDir, id, reportFile)
	if err := writeJSON(w.root, name+".tmp", r); err != nil {
		return fmt.Errorf("runs: write the report: %w", err)
	}
	if err := w.root.Rename(name+".tmp", name); err != nil {
		return fmt.Errorf("runs: write the report: %w", err)
	}
	return nil
}

// evaluate gives the verdict on a, which has been drained, so nothing can
// change what it reads.
func (m *Manager) evaluate(a *activeRun, drained Drained) (Report, error) {
	s := a.run.Scenario
	set := a.rules.Rules()
	trace := a.events.Trace()
	r := Report{
		SchemaVersion: reportVersion,
		Run:           ReportRun{ID: a.run.ID, Started: a.run.Started, Scenario: s.Name, Inline: s.Inline, Seed: strconv.FormatUint(uint64(s.Seed), 10), SeedPinned: s.Pinned},
		Assertions:    []AssertionResult{},
		Unfinished:    drained.Unfinished,
		Interactive:   set.Revision > 1,
		Rules:         make(map[string]RuleResult, len(set.Counts)),
		Trace:         TraceResult{Bytes: trace.Size, Complete: trace.Complete},
		Files:         []FinalFile{},
	}
	if trace.Err != nil {
		r.Trace.Error = trace.Err.Error()
	}
	for id, c := range set.Counts {
		r.Rules[id] = RuleResult{Matched: c.Matched, Selected: c.Selected, Fired: c.Fired}
	}
	files, _, err := m.Files(a.run.ID, "/", true)
	if err != nil {
		return Report{}, err
	}
	final := make(map[string]File, len(files))
	for _, f := range files {
		final[f.Path] = f
		if !f.Dir {
			r.Files = append(r.Files, FinalFile{Path: f.Path, Size: f.Size, SHA256: f.SHA256})
		}
	}
	copies, err := m.Snapshots(a.run.ID, false)
	if err != nil {
		return Report{}, err
	}
	r.Snapshots = len(copies)

	listed, err := config.AssertionsJSON(a.assertions)
	if err != nil {
		return Report{}, err
	}
	var written []json.RawMessage
	if err := json.Unmarshal(listed, &written); err != nil {
		return Report{}, fmt.Errorf("runs: read the assertions: %w", err)
	}
	r.Passed = len(a.assertions) > 0 && len(drained.Unfinished) == 0
	if len(a.assertions) == 0 {
		r.Problems = append(r.Problems, "the run states no assertions, so nothing was checked")
	}
	for _, p := range drained.Unfinished {
		r.Problems = append(r.Problems, "the transfer of "+p+" was unfinished: its handle was still open when the drain ended its connection")
	}
	check := evaluation{manager: m, run: a.run.ID, counts: set.Counts, files: final, trace: trace}
	for i, assertion := range a.assertions {
		passed, detail := check.assertion(assertion)
		r.Passed = r.Passed && passed
		r.Assertions = append(r.Assertions, AssertionResult{Assertion: written[i], Description: assertion.String(), Passed: passed, Detail: detail})
	}
	return r, nil
}

// evaluation is what the assertions of a drained run are checked against.
type evaluation struct {
	manager *Manager
	run     string
	counts  map[string]faults.Counts
	files   map[string]File
	trace   events.TraceStatus
}

func (e evaluation) assertion(a config.Assertion) (passed bool, detail string) {
	switch a.Type {
	case config.RuleFired:
		c, ok := e.counts[a.Rule]
		if !ok {
			return false, "the rule was removed during the run, so its count is gone"
		}
		return a.Count.Allows(c.Fired), "fired " + times(c.Fired)
	case config.SuccessfulOperation:
		if !e.trace.Complete {
			return false, "the trace is incomplete, so it may not hold every request: " + e.traceProblem()
		}
		n, err := e.manager.countOperations(e.run, a)
		if err != nil {
			return false, "the trace cannot be read: " + err.Error()
		}
		return a.Count.Allows(n), "succeeded " + times(n)
	case config.FileEqualsFixture:
		return e.fileEqualsFixture(a)
	case config.FileHash:
		f, problem := e.file(a.Path)
		if problem != "" {
			return false, problem
		}
		if f.SHA256 != a.SHA256 {
			return false, fmt.Sprintf("holds %d bytes with sha256 %s", f.Size, f.SHA256)
		}
		return true, fmt.Sprintf("holds %d bytes with that hash", f.Size)
	case config.PathAbsent:
		f, ok := e.files[a.Path]
		switch {
		case !ok:
			return true, "nothing is there"
		case f.Dir:
			return false, "a directory is there"
		}
		return false, fmt.Sprintf("a file of %d bytes is there", f.Size)
	}
	return false, fmt.Sprintf("sftpit cannot check an assertion of type %s", a.Type)
}

func (e evaluation) fileEqualsFixture(a config.Assertion) (passed bool, detail string) {
	f, problem := e.file(a.Path)
	if problem != "" {
		return false, problem
	}
	var want *fixtureEntry
	if s := e.manager.expected; s != nil {
		for _, entry := range s.manifest.Entries {
			if entry.Type == "file" && entry.Path == a.Fixture {
				want = &entry
				break
			}
		}
	}
	if want == nil {
		return false, "the fixture is not in the snapshot of expected_dir taken when sftpit started"
	}
	if f.SHA256 != want.SHA256 {
		return false, fmt.Sprintf("holds %d bytes with sha256 %s; the fixture holds %d bytes with sha256 %s", f.Size, f.SHA256, want.Size, want.SHA256)
	}
	return true, fmt.Sprintf("holds the fixture's %d bytes", f.Size)
}

// file returns the file at name, or says why there is none.
func (e evaluation) file(name string) (File, string) {
	f, ok := e.files[name]
	switch {
	case !ok:
		return File{}, "no file is there"
	case f.Dir:
		return File{}, "a directory is there, not a file"
	}
	return f, ""
}

func (e evaluation) traceProblem() string {
	if e.trace.Err != nil {
		return e.trace.Err.Error()
	}
	return "it reached events.max_disk_bytes"
}

func times(n uint64) string {
	if n == 1 {
		return "1 time"
	}
	return fmt.Sprintf("%d times", n)
}

// assertedRequests are the requests that each operation that
// config.SuccessfulOperation counts is made of, as events name them, with
// the reply that means success.
var assertedRequests = map[faults.Operation]struct {
	requests []string
	success  string
}{
	faults.Rename:  {[]string{"SSH_FXP_RENAME", "posix-rename@openssh.com"}, "SSH_FX_OK"},
	faults.Remove:  {[]string{"SSH_FXP_REMOVE"}, "SSH_FX_OK"},
	faults.Mkdir:   {[]string{"SSH_FXP_MKDIR"}, "SSH_FX_OK"},
	faults.Rmdir:   {[]string{"SSH_FXP_RMDIR"}, "SSH_FX_OK"},
	faults.SetStat: {[]string{"SSH_FXP_SETSTAT", "SSH_FXP_FSETSTAT"}, "SSH_FX_OK"},
	faults.Stat:    {[]string{"SSH_FXP_STAT"}, "SSH_FXP_ATTRS"},
	faults.LStat:   {[]string{"SSH_FXP_LSTAT"}, "SSH_FXP_ATTRS"},
}

// countOperations counts the requests in run's trace that a counts and that
// got a successful reply.
func (m *Manager) countOperations(run string, a config.Assertion) (uint64, error) {
	f, size, err := m.OpenTrace(run)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	want, ok := assertedRequests[a.Operation]
	if !ok {
		return 0, fmt.Errorf("runs: no request is recorded as %s", a.Operation)
	}
	dec := json.NewDecoder(io.NewSectionReader(f, 0, size))
	var n uint64
	for {
		var e struct {
			Kind    events.Kind `json:"kind"`
			Request string      `json:"request"`
			Path    string      `json:"path"`
			Target  string      `json:"target"`
			Reply   string      `json:"reply"`
		}
		if err := dec.Decode(&e); errors.Is(err, io.EOF) {
			return n, nil
		} else if err != nil {
			return 0, fmt.Errorf("runs: read the trace: %w", err)
		}
		if e.Kind != events.Operation || e.Reply != want.success {
			continue
		}
		if !slices.Contains(want.requests, e.Request) {
			continue
		}
		if a.Operation == faults.Rename {
			if (a.Source == "" || a.Source == e.Path) && (a.Target == "" || a.Target == e.Target) {
				n++
			}
		} else if a.Path == e.Path {
			n++
		}
	}
}
