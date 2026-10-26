package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{
			name:       "no command prints usage as an error",
			args:       nil,
			wantCode:   exitUsage,
			wantStderr: "Usage: sftpit <command>",
		},
		{
			name:       "version",
			args:       []string{"version"},
			wantCode:   exitOK,
			wantStdout: "sftpit ",
		},
		{
			name:       "unknown command with flags",
			args:       []string{"server", "--config", "x.yaml"},
			wantCode:   exitUsage,
			wantStderr: `unknown command "server"`,
		},
		{
			name:       "help",
			args:       []string{"help"},
			wantCode:   exitOK,
			wantStdout: "Usage: sftpit <command>",
		},
		{
			name:       "help flag",
			args:       []string{"--help"},
			wantCode:   exitOK,
			wantStdout: "Usage: sftpit <command>",
		},
		{
			name:       "unknown command",
			args:       []string{"serve-all"},
			wantCode:   exitUsage,
			wantStderr: `unknown command "serve-all"`,
		},
		{
			name:       "unexpected arguments",
			args:       []string{"version", "--json"},
			wantCode:   exitUsage,
			wantStderr: `unexpected arguments ["--json"]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := run(commandContext(t), tt.args, &stdout, &stderr)

			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			assertOutput(t, "stdout", stdout.String(), tt.wantStdout)
			assertOutput(t, "stderr", stderr.String(), tt.wantStderr)
		})
	}
}

func assertOutput(t *testing.T, stream, got, want string) {
	t.Helper()
	if want == "" {
		if got != "" {
			t.Errorf("%s = %q, want empty", stream, got)
		}
		return
	}
	if !strings.Contains(got, want) {
		t.Errorf("%s = %q, want it to contain %q", stream, got, want)
	}
}
