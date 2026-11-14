package config

import (
	"errors"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
	"github.com/nebarg/sftpit/internal/sshfront"
)

func TestFaultsCompileToEngineRules(t *testing.T) {
	ops := func(o ...faults.Operation) []faults.Operation { return o }
	commands := ops(faults.List, faults.Stat, faults.LStat, faults.FStat, faults.OpenRead, faults.OpenWrite, faults.Close, faults.Rename, faults.Remove, faults.Mkdir, faults.Rmdir, faults.SetStat)
	denied := sftpproxy.Fail{Status: sftpwire.StatusPermissionDenied}
	removes := faults.Match{Operations: ops(faults.Remove)}
	tests := []struct {
		name  string
		fault Fault
		want  faults.Rule
	}{
		{"deletes fail", Fault{Preset: "deletes_fail"}, faults.Rule{Match: removes, Action: denied}},
		{"renames fail in a folder", Fault{Preset: "renames_fail", Folder: "/outgoing"},
			faults.Rule{Match: faults.Match{Operations: ops(faults.Rename), Path: faults.Location{Kind: faults.Under, Pattern: "/outgoing"}}, Action: denied}},
		{"an upload stops partway", Fault{Preset: "upload_stops_partway"},
			faults.Rule{Match: faults.Match{Operations: ops(faults.Write)}, Action: sftpproxy.PartialUpload{Cutoff: 32 << 10, Result: sftpproxy.Drop{}}}},
		{"a download stops abruptly after 1 KB", Fault{Preset: "download_stops_partway", KB: new(uint64(1)), Abrupt: true},
			faults.Rule{Match: faults.Match{Operations: ops(faults.Read)}, Action: sftpproxy.PartialDownload{Cutoff: 1 << 10, Result: sftpproxy.Drop{Reset: true}}}},
		{"an upload stopped with an error", Fault{Preset: "upload_stops_partway", Error: "failure"},
			faults.Rule{Match: faults.Match{Operations: ops(faults.Write)}, Action: sftpproxy.PartialUpload{Cutoff: 32 << 10, Result: sftpproxy.Fail{Status: sftpwire.StatusFailure}}}},
		{"a download stopped with an error after 1 MB", Fault{Preset: "download_stops_partway", KB: new(uint64(1024)), Error: "permission_denied"},
			faults.Rule{Match: faults.Match{Operations: ops(faults.Read)}, Action: sftpproxy.PartialDownload{Cutoff: 1 << 20, Result: denied}}},
		{"an upload cut short after 3 MB", Fault{Steps: []string{"write"}, Do: "truncate", KB: new(uint64(3072))},
			faults.Rule{Match: faults.Match{Operations: ops(faults.Write)}, Action: sftpproxy.CorruptUpload{Corruption: sftpproxy.Truncate, Offset: 3 << 20}}},
		{"each file's second download cut short", Fault{Steps: []string{"read"}, Do: "truncate", Only: new(uint64(2))},
			faults.Rule{Match: faults.Match{Operations: ops(faults.Read), Attempt: &faults.Attempt{PerPath: true, Numbers: []uint64{2}}}, Action: sftpproxy.CorruptDownload{Corruption: sftpproxy.Truncate, Offset: 32 << 10}}},
		{"a corrupted download", Fault{Preset: "download_corrupted", Names: "*.csv"},
			faults.Rule{Match: faults.Match{Operations: ops(faults.Read), Path: faults.Location{Kind: faults.NamedGlob, Pattern: "*.csv"}}, Action: sftpproxy.CorruptDownload{Corruption: sftpproxy.FlipBytes, Length: 64}}},
		{"a file goes missing", Fault{Preset: "file_goes_missing", File: "/outgoing/report.csv"},
			faults.Rule{Match: faults.Match{Operations: ops(faults.OpenRead, faults.Stat, faults.LStat), Path: faults.Location{Kind: faults.Exactly, Pattern: "/outgoing/report.csv"}}, Action: sftpproxy.Hide{}}},
		{"slow responses", Fault{Preset: "slow_responses"},
			faults.Rule{Match: faults.Match{Operations: commands}, Action: sftpproxy.Delay{Duration: 3 * time.Second}}},
		{"slow responses of 1.5 s for one user", Fault{Preset: "slow_responses", Seconds: new(1.5), User: "partner-b"},
			faults.Rule{Match: faults.Match{Operations: commands, User: "partner-b"}, Action: sftpproxy.Delay{Duration: 1500 * time.Millisecond}}},
		{"dropped connections", Fault{Preset: "connection_drops"}, faults.Rule{Match: faults.Match{Operations: commands}, Action: sftpproxy.Drop{}}},
		{"the server goes down at once", Fault{Preset: "server_goes_down"},
			faults.Rule{Trigger: &faults.Trigger{Anchor: faults.Run, At: &faults.Range[time.Duration]{}}, Action: sftpproxy.ListenerDown{Duration: 30 * time.Second, CloseExisting: true}}},
		{"logins fail", Fault{Preset: "logins_fail"}, faults.Rule{Match: faults.Match{Operations: ops(faults.Authenticate)}, Action: sftpproxy.Drop{}}},
		{"a delete refused after it happens", Fault{Steps: []string{"remove"}, Do: "refuse", After: true},
			faults.Rule{Match: removes, Action: sftpproxy.Fail{When: sftpproxy.After, Status: sftpwire.StatusFailure}}},
		{"a held listing", Fault{Steps: []string{"list"}, Do: "hold"},
			faults.Rule{Match: faults.Match{Operations: ops(faults.List)}, Action: sftpproxy.Stall{Limit: 10 * time.Minute}}},
		{"a frozen upload start", Fault{Steps: []string{"open_write"}, Do: "freeze"},
			faults.Rule{Match: faults.Match{Operations: ops(faults.OpenWrite)}, Action: sftpproxy.Freeze{Limit: time.Minute}}},
		{"a corrupted upload", Fault{Steps: []string{"write"}, Do: "corrupt"},
			faults.Rule{Match: faults.Match{Operations: ops(faults.Write)}, Action: sftpproxy.CorruptUpload{Corruption: sftpproxy.FlipBytes, Length: 64}}},
		{"wrong sizes", Fault{Steps: []string{"stat", "list"}, Do: "wrong_size"},
			faults.Rule{Match: faults.Match{Operations: ops(faults.Stat, faults.LStat, faults.FStat, faults.List)}, Action: sftpproxy.WrongSize{Delta: -1024}}},
		{"a slow login", Fault{Steps: []string{"authenticate"}, Do: "wait", Seconds: new(2.0)},
			faults.Rule{Match: faults.Match{Operations: ops(faults.Authenticate)}, Action: sftpproxy.Delay{Duration: 2 * time.Second}}},
		{"the server goes down at a rename", Fault{Steps: []string{"rename"}, Do: "down", Seconds: new(5.0)},
			faults.Rule{Match: faults.Match{Operations: ops(faults.Rename)}, Action: sftpproxy.ListenerDown{Duration: 5 * time.Second, CloseExisting: true}}},
		{"the first two times", Fault{Preset: "deletes_fail", First: new(uint64(2))}, faults.Rule{MaxTriggers: 2, Match: removes, Action: denied}},
		{"only the second time", Fault{Preset: "deletes_fail", Only: new(uint64(2))},
			faults.Rule{Match: faults.Match{Operations: ops(faults.Remove), Occurrence: []uint64{2}}, Action: denied}},
		{"only each file's second upload", Fault{Preset: "upload_stops_partway", Only: new(uint64(2))},
			faults.Rule{Match: faults.Match{Operations: ops(faults.Write), Attempt: &faults.Attempt{PerPath: true, Numbers: []uint64{2}}}, Action: sftpproxy.PartialUpload{Cutoff: 32 << 10, Result: sftpproxy.Drop{}}}},
		{"a quarter of the time", Fault{Preset: "deletes_fail", Percent: new(25.0)}, faults.Rule{Match: removes, Probability: new(0.25), Action: denied}},
		{"for the next 5 minutes", Fault{Preset: "deletes_fail", Minutes: new(5.0)},
			faults.Rule{Match: removes, Trigger: &faults.Trigger{Anchor: faults.Run, Window: &faults.Window{Until: 5 * time.Minute}}, Action: denied}},
		{"the most first times", Fault{Preset: "deletes_fail", First: new(uint64(math.MaxInt))}, faults.Rule{MaxTriggers: math.MaxInt, Match: removes, Action: denied}},
		{"only the last time there can be", Fault{Preset: "deletes_fail", Only: new(uint64(math.MaxUint64))},
			faults.Rule{Match: faults.Match{Operations: ops(faults.Remove), Occurrence: []uint64{math.MaxUint64}}, Action: denied}},
		{"every time, by percent", Fault{Preset: "deletes_fail", Percent: new(100.0)}, faults.Rule{Match: removes, Probability: new(1.0), Action: denied}},
		{"for the most minutes", Fault{Preset: "deletes_fail", Minutes: new(153722867.280912)},
			faults.Rule{Match: removes, Trigger: &faults.Trigger{Anchor: faults.Run, Window: &faults.Window{Until: 9223372036854720512}}, Action: denied}},
		{"the longest wait", Fault{Steps: []string{"remove"}, Do: "wait", Seconds: new(9223372036.854775)},
			faults.Rule{Match: removes, Action: sftpproxy.Delay{Duration: 9223372036854774784}}},
		{"the shortest wait", Fault{Steps: []string{"remove"}, Do: "wait", Seconds: new(1e-9)},
			faults.Rule{Match: removes, Action: sftpproxy.Delay{Duration: time.Nanosecond}}},
		{"a download stopped after the most KB", Fault{Preset: "download_stops_partway", KB: new(uint64(math.MaxUint64 / 1024))},
			faults.Rule{Match: faults.Match{Operations: ops(faults.Read)}, Action: sftpproxy.PartialDownload{Cutoff: math.MaxUint64 - 1023, Result: sftpproxy.Drop{}}}},
		{"an upload cut short after the most KB", Fault{Steps: []string{"write"}, Do: "truncate", KB: new(uint64(math.MaxUint64 / 1024))},
			faults.Rule{Match: faults.Match{Operations: ops(faults.Write)}, Action: sftpproxy.CorruptUpload{Corruption: sftpproxy.Truncate, Offset: math.MaxUint64 - 1023}}},
		{"sizes off by the most below", Fault{Steps: []string{"stat"}, Do: "wrong_size", SizeOffBy: new(int64(math.MinInt64))},
			faults.Rule{Match: faults.Match{Operations: ops(faults.Stat, faults.LStat, faults.FStat)}, Action: sftpproxy.WrongSize{Delta: math.MinInt64}}},
		{"sizes off by the most above", Fault{Steps: []string{"stat"}, Do: "wrong_size", SizeOffBy: new(int64(math.MaxInt64))},
			faults.Rule{Match: faults.Match{Operations: ops(faults.Stat, faults.LStat, faults.FStat)}, Action: sftpproxy.WrongSize{Delta: math.MaxInt64}}},
	}
	users := []sshfront.User{{Name: "test"}, {Name: "partner-b"}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.fault.Rule("r", users)
			if err != nil {
				t.Fatalf("Rule: %v", err)
			}
			tt.want.ID = "r"
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("the fault compiles to\n%+v\nwant\n%+v", got, tt.want)
			}
			if err := faults.Check([]faults.Rule{got}); err != nil {
				t.Errorf("the engine refuses the rule: %v", err)
			}
		})
	}
}

func TestEveryPresetCompiles(t *testing.T) {
	for _, p := range Presets {
		if _, err := (Fault{Preset: p.ID}).Rule("r", testUsers); err != nil {
			t.Errorf("preset %s: %v", p.ID, err)
		}
	}
}

func TestResolveFillsInThePresetAndDefaults(t *testing.T) {
	got, err := Fault{Preset: "slow_responses", Folder: "/in"}.Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Name != "Slow responses" || got.Do != "wait" || *got.Seconds != 3 || got.Folder != "/in" || len(got.Steps) == 0 {
		t.Errorf("Resolve = %+v, want the preset's name, action, steps and seconds, and the folder", got)
	}
	if again, err := got.Resolve(); err != nil || !reflect.DeepEqual(again, got) {
		t.Errorf("resolving again = %+v, %v; want the same fault", again, err)
	}
	got, err = Fault{Steps: []string{"remove"}, Do: "refuse"}.Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Name != "Custom fault" || got.Error != "failure" {
		t.Errorf("Resolve = %+v, want the name Custom fault and the error failure", got)
	}
}

func TestFaultsRejectWhatTheyCannotDo(t *testing.T) {
	tests := []struct {
		name  string
		fault Fault
		want  string
	}{
		{"no preset or action", Fault{}, "say what to do, or choose a preset"},
		{"an unknown preset", Fault{Preset: "oops"}, `there is no preset "oops"`},
		{"a preset with steps", Fault{Preset: "deletes_fail", Steps: []string{"rename"}}, "the preset deletes_fail sets the steps and what to do"},
		{"an unknown action", Fault{Steps: []string{"remove"}, Do: "explode"}, `there is nothing to do called "explode"`},
		{"no steps", Fault{Do: "refuse"}, "choose at least one step"},
		{"an unknown step", Fault{Steps: []string{"upload"}, Do: "refuse"}, `there is no step "upload"; the steps are connect, authenticate`},
		{"an unknown error", Fault{Steps: []string{"remove"}, Do: "refuse", Error: "oops"}, `error "oops" is not one of failure, no_such_file, permission_denied, unsupported`},
		{"two locations", Fault{Preset: "deletes_fail", Folder: "/a", File: "/a/b"}, "choose one of folder, file and names"},
		{"two frequencies", Fault{Preset: "deletes_fail", First: new(uint64(1)), Percent: new(5.0)}, "choose one of first, only, percent and minutes"},
		{"login and a command", Fault{Steps: []string{"authenticate", "remove"}, Do: "drop"}, "connecting and logging in can't be combined with other steps"},
		{"login in a folder", Fault{Steps: []string{"authenticate"}, Do: "drop", Folder: "/a"}, "connecting and logging in have no file"},
		{"a refused login", Fault{Steps: []string{"authenticate"}, Do: "refuse"}, "can't be refused with an error"},
		{"a held connection", Fault{Steps: []string{"connect"}, Do: "hold"}, "can't be held"},
		{"a login after the server acts", Fault{Steps: []string{"authenticate"}, Do: "wait", After: true}, "connecting and logging in have no before or after"},
		{"a stop that is not a transfer", Fault{Steps: []string{"rename"}, Do: "stop_partway"}, "stopping partway applies to writing file data or reading it"},
		{"a stop both ways", Fault{Steps: []string{"read", "write"}, Do: "stop_partway"}, "choose one of them"},
		{"a corruption after the server acts", Fault{Steps: []string{"read"}, Do: "corrupt", After: true}, "corrupt can't act after the server"},
		{"a stop with an error and abruptly", Fault{Preset: "upload_stops_partway", Error: "failure", Abrupt: true}, "either answers with an error or closes the connection abruptly"},
		{"a stop with an unknown error", Fault{Preset: "upload_stops_partway", Error: "oops"}, `error "oops" is not one of`},
		{"a rename cut short", Fault{Steps: []string{"rename"}, Do: "truncate"}, "cutting a file short applies to writing file data or reading it"},
		{"a cut after the server acts", Fault{Steps: []string{"write"}, Do: "truncate", After: true}, "truncate can't act after the server"},
		{"a wrong size on a delete", Fault{Steps: []string{"remove"}, Do: "wrong_size"}, "a wrong size applies only to the steps stat, list"},
		{"a hidden upload", Fault{Steps: []string{"open_write"}, Do: "hide"}, "hiding a file applies only to the steps"},
		{"no seconds", Fault{Steps: []string{"remove"}, Do: "wait", Seconds: new(0.0)}, "seconds must be above 0"},
		{"less than a nanosecond", Fault{Steps: []string{"remove"}, Do: "wait", Seconds: new(1e-10)}, "seconds must be above 0"},
		{"a size off by nothing", Fault{Steps: []string{"stat"}, Do: "wrong_size", SizeOffBy: new(int64(0))}, "size_off_by can't be 0"},
		{"a down at once in a folder", Fault{Preset: "server_goes_down", Folder: "/a"}, "a server that goes down at once has no files"},
		{"a down at once for some minutes", Fault{Preset: "server_goes_down", Minutes: new(1.0)}, "can't also last for some minutes"},
		{"zero first times", Fault{Preset: "deletes_fail", First: new(uint64(0))}, "first must be at least 1"},
		{"time number zero", Fault{Preset: "deletes_fail", Only: new(uint64(0))}, "only must be at least 1"},
		{"a percent above 100", Fault{Preset: "deletes_fail", Percent: new(150.0)}, "percent must be above 0 and at most 100"},
		{"no minutes", Fault{Preset: "deletes_fail", Minutes: new(0.0)}, "minutes must be above 0"},
		{"seconds that are not a number", Fault{Steps: []string{"remove"}, Do: "wait", Seconds: new(math.NaN())}, "seconds must be above 0"},
		{"seconds below every number", Fault{Steps: []string{"remove"}, Do: "hold", Seconds: new(math.Inf(-1))}, "seconds must be above 0"},
		{"seconds beyond every number", Fault{Steps: []string{"remove"}, Do: "wait", Seconds: new(math.Inf(1))}, "seconds must be at most 9223372036.854775"},
		{"seconds just beyond the longest", Fault{Steps: []string{"list"}, Do: "freeze", Seconds: new(9223372036.854776)}, "seconds must be at most 9223372036.854775"},
		{"a server down for too long", Fault{Preset: "server_goes_down", Seconds: new(1e300)}, "seconds must be at most 9223372036.854775"},
		{"kb that comes to 0 bytes", Fault{Preset: "upload_stops_partway", KB: new(uint64(1 << 54))}, "kb must be at most 18014398509481983"},
		{"kb just beyond the most", Fault{Steps: []string{"read"}, Do: "truncate", KB: new(uint64(math.MaxUint64/1024 + 1))}, "kb must be at most 18014398509481983"},
		{"the largest kb", Fault{Preset: "download_stops_partway", KB: new(uint64(math.MaxUint64))}, "kb must be at most 18014398509481983"},
		{"first beyond the most times", Fault{Preset: "deletes_fail", First: new(uint64(1 << 63))}, "first must be at most 9223372036854775807"},
		{"the largest first", Fault{Preset: "deletes_fail", First: new(uint64(math.MaxUint64))}, "first must be at most 9223372036854775807"},
		{"a percent that is not a number", Fault{Preset: "deletes_fail", Percent: new(math.NaN())}, "percent must be above 0 and at most 100"},
		{"a percent beyond every number", Fault{Preset: "deletes_fail", Percent: new(math.Inf(1))}, "percent must be above 0 and at most 100"},
		{"a percent below every number", Fault{Preset: "deletes_fail", Percent: new(math.Inf(-1))}, "percent must be above 0 and at most 100"},
		{"minutes that are not a number", Fault{Preset: "deletes_fail", Minutes: new(math.NaN())}, "minutes must be above 0"},
		{"minutes below every number", Fault{Preset: "deletes_fail", Minutes: new(math.Inf(-1))}, "minutes must be above 0"},
		{"less than a nanosecond of minutes", Fault{Preset: "deletes_fail", Minutes: new(1e-12)}, "minutes must be above 0"},
		{"minutes beyond every number", Fault{Preset: "deletes_fail", Minutes: new(math.Inf(1))}, "minutes must be at most 153722867.280912"},
		{"minutes just beyond the most", Fault{Preset: "deletes_fail", Minutes: new(153722867.280913)}, "minutes must be at most 153722867.280912"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.fault.Rule("r", testUsers)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Rule error = %v, want it to contain %q", err, tt.want)
			}
			if !errors.Is(err, ErrInvalidFault) {
				t.Errorf("Rule error = %v, want ErrInvalidFault", err)
			}
		})
	}
	_, err := (Fault{Preset: "deletes_fail", User: "nobody"}).Rule("r", []sshfront.User{{Name: "test", Password: "x"}})
	if err == nil || !strings.Contains(err.Error(), `user "nobody" is not a configured user`) {
		t.Errorf("Rule error = %v, want an unknown user refused", err)
	}
	if !errors.Is(err, ErrInvalidFault) {
		t.Errorf("Rule error = %v, want ErrInvalidFault", err)
	}
}

func TestAnInvalidFaultSaysOnlyWhatIsWrong(t *testing.T) {
	for _, f := range []Fault{{Preset: "oops"}, {Steps: []string{"remove"}, Do: "explode"}, {Preset: "deletes_fail", User: "nobody"}} {
		_, _, err := f.Compile(testUsers)
		if !errors.Is(err, ErrInvalidFault) || strings.Contains(err.Error(), ErrInvalidFault.Error()) {
			t.Errorf("Compile(%+v) error = %q, want ErrInvalidFault without its text", f, err)
		}
	}
	if _, err := (Fault{Do: "refuse"}).Resolve(); !errors.Is(err, ErrInvalidFault) || err.Error() != "choose at least one step" {
		t.Errorf("Resolve error = %v, want ErrInvalidFault saying to choose a step", err)
	}
}

func TestCompileResolvesAndCompilesTheFault(t *testing.T) {
	f := Fault{Preset: "slow_responses", Folder: "/in", User: "test"}
	resolved, rule, err := f.Compile(testUsers)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if want, err := f.Resolve(); err != nil || !reflect.DeepEqual(resolved, want) {
		t.Errorf("Compile resolves to %+v, want %+v as Resolve gives it", resolved, want)
	}
	want, err := f.Rule("r", testUsers)
	if err != nil {
		t.Fatalf("Rule: %v", err)
	}
	if want.ID = ""; !reflect.DeepEqual(rule, want) {
		t.Errorf("Compile gives the rule\n%+v\nwant Rule's, without an ID\n%+v", rule, want)
	}
}

func TestActionsListWhatAFaultCanDo(t *testing.T) {
	want := []string{"refuse", "wait", "hold", "drop", "freeze", "stop_partway", "corrupt", "truncate", "wrong_size", "hide", "down"}
	ids := make([]string, len(Actions))
	for i, a := range Actions {
		ids[i] = a.ID
		if a.Name == "" {
			t.Errorf("action %s has no name", a.ID)
		}
	}
	if !slices.Equal(ids, want) {
		t.Errorf("Actions are %v, want %v", ids, want)
	}
}
