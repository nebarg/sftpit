package config

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/sshfront"
)

func TestFaultsCompileToTheirLongForm(t *testing.T) {
	commands := "[list, stat, lstat, fstat, open_read, open_write, close, rename, remove, mkdir, rmdir, setstat]"
	tests := []struct {
		name  string
		fault Fault
		long  string
	}{
		{"deletes fail", Fault{Preset: "deletes_fail"},
			`match: {operation: remove}
        action: {type: fail, when: before, status: permission_denied}`},
		{"renames fail in a folder", Fault{Preset: "renames_fail", Folder: "/outgoing"},
			`match: {operation: rename, path_prefix: /outgoing}
        action: {type: fail, when: before, status: permission_denied}`},
		{"an upload stops partway", Fault{Preset: "upload_stops_partway"},
			`match: {operation: write}
        action: {type: partial_upload, cutoff_offset: 32768, result: close_connection, mode: fin}`},
		{"a download stops abruptly after 1 KB", Fault{Preset: "download_stops_partway", KB: new(uint64(1)), Abrupt: true},
			`match: {operation: read}
        action: {type: partial_download, cutoff_offset: 1024, result: close_connection, mode: rst}`},
		{"a corrupted download", Fault{Preset: "download_corrupted", Names: "*.csv"},
			`match: {operation: read, filename_glob: "*.csv"}
        action: {type: corrupt_download, transform: flip_bytes, offset: 0, length: 64}`},
		{"a file goes missing", Fault{Preset: "file_goes_missing", File: "/outgoing/report.csv"},
			`match: {operation: [open_read, stat, lstat], path: /outgoing/report.csv}
        action: {type: hide}`},
		{"slow responses", Fault{Preset: "slow_responses"},
			`match: {operation: ` + commands + `}
        action: {type: delay, when: before, duration: 3s}`},
		{"slow responses of 1.5 s for one user", Fault{Preset: "slow_responses", Seconds: new(1.5), User: "partner-b"},
			`match: {operation: ` + commands + `, user: partner-b}
        action: {type: delay, when: before, duration: 1.5s}`},
		{"dropped connections", Fault{Preset: "connection_drops"},
			`match: {operation: ` + commands + `}
        action: {type: close_connection, when: before, mode: fin}`},
		{"the server goes down at once", Fault{Preset: "server_goes_down"},
			`trigger: {at: 0s, anchor: run}
        action: {type: listener_down, duration: 30s, close_existing: true}`},
		{"logins fail", Fault{Preset: "logins_fail"},
			`match: {operation: authenticate}
        action: {type: close_connection, mode: fin}`},
		{"a delete refused after it happens", Fault{Steps: []string{"remove"}, Do: "refuse", After: true},
			`match: {operation: remove}
        action: {type: fail, when: after, status: failure}`},
		{"a held listing", Fault{Steps: []string{"list"}, Do: "hold"},
			`match: {operation: list}
        action: {type: stall, when: before, max_stall: 10m0s}`},
		{"a frozen upload start", Fault{Steps: []string{"open_write"}, Do: "freeze"},
			`match: {operation: open_write}
        action: {type: freeze_connection, when: before, max_freeze: 1m0s}`},
		{"a corrupted upload", Fault{Steps: []string{"write"}, Do: "corrupt"},
			`match: {operation: write}
        action: {type: corrupt_upload, transform: flip_bytes, offset: 0, length: 64}`},
		{"wrong sizes", Fault{Steps: []string{"stat", "list"}, Do: "wrong_size"},
			`match: {operation: [stat, lstat, fstat, list]}
        action: {type: wrong_size, size_delta: -1024}`},
		{"a slow login", Fault{Steps: []string{"authenticate"}, Do: "wait", Seconds: new(2.0)},
			`match: {operation: authenticate}
        action: {type: delay, duration: 2s}`},
		{"the server goes down at a rename", Fault{Steps: []string{"rename"}, Do: "down", Seconds: new(5.0)},
			`match: {operation: rename}
        action: {type: listener_down, when: before, duration: 5s, close_existing: true}`},
		{"the first two times", Fault{Preset: "deletes_fail", First: new(uint64(2))},
			`max_triggers: 2
        match: {operation: remove}
        action: {type: fail, when: before, status: permission_denied}`},
		{"only the second time", Fault{Preset: "deletes_fail", Only: new(uint64(2))},
			`match: {operation: remove, occurrence: [2]}
        action: {type: fail, when: before, status: permission_denied}`},
		{"only each file's second upload", Fault{Preset: "upload_stops_partway", Only: new(uint64(2))},
			`match: {operation: write, attempt: {per: [path], numbers: [2]}}
        action: {type: partial_upload, cutoff_offset: 32768, result: close_connection, mode: fin}`},
		{"a quarter of the time", Fault{Preset: "deletes_fail", Percent: new(25.0)},
			`match: {operation: remove}
        decision: {probability: 0.25}
        action: {type: fail, when: before, status: permission_denied}`},
		{"for the next 5 minutes", Fault{Preset: "deletes_fail", Minutes: new(5.0)},
			`match: {operation: remove}
        trigger: {window: {from: 0s, until: 5m0s}, anchor: run}
        action: {type: fail, when: before, status: permission_denied}`},
	}
	dir := t.TempDir()
	writeAuthorizedKeys(t, filepath.Join(dir, "partner-b.pub"), "")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := loadScenarios(t, dir, oneRule(tt.long), "")
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			want := cfg.Scenarios["s"].Rules[0]
			got, err := tt.fault.Rule("r", cfg.Users)
			if err != nil {
				t.Fatalf("Rule: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("the fault compiles to\n%+v\nwant, as from the long form,\n%+v", got, want)
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
		{"a wrong size on a delete", Fault{Steps: []string{"remove"}, Do: "wrong_size"}, "a wrong size applies only to the steps stat, list"},
		{"a hidden upload", Fault{Steps: []string{"open_write"}, Do: "hide"}, "hiding a file applies only to the steps"},
		{"no seconds", Fault{Steps: []string{"remove"}, Do: "wait", Seconds: new(0.0)}, "seconds must be above 0"},
		{"a down at once in a folder", Fault{Preset: "server_goes_down", Folder: "/a"}, "a server that goes down at once has no files"},
		{"a down at once for some minutes", Fault{Preset: "server_goes_down", Minutes: new(1.0)}, "can't also last for some minutes"},
		{"zero first times", Fault{Preset: "deletes_fail", First: new(uint64(0))}, "first must be at least 1"},
		{"time number zero", Fault{Preset: "deletes_fail", Only: new(uint64(0))}, "only must be at least 1"},
		{"a percent above 100", Fault{Preset: "deletes_fail", Percent: new(150.0)}, "percent must be above 0 and at most 100"},
		{"no minutes", Fault{Preset: "deletes_fail", Minutes: new(0.0)}, "minutes must be above 0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.fault.Rule("r", testUsers)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Rule error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
	if _, err := (Fault{Preset: "deletes_fail", User: "nobody"}).Rule("r", []sshfront.User{{Name: "test", Password: "x"}}); err == nil || !strings.Contains(err.Error(), `user "nobody" is not a configured user`) {
		t.Errorf("Rule error = %v, want an unknown user refused", err)
	}
}
