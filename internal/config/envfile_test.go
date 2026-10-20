package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParseEnvAcceptsTheSupportedForms(t *testing.T) {
	data := "# a comment\r\n" +
		"\n" +
		"  # an indented comment\n" +
		"PLAIN=value\n" +
		"export EXPORTED=exported\n" +
		"SINGLE='a $literal \\ \"quote\"'\n" +
		"DOUBLE=\"two words\"\n" +
		"EMPTY=\n" +
		"COMMENTED=value # a comment\n" +
		"QUOTED_COMMENTED='value' # a comment\n" +
		"HASH=abc#def\n" +
		"CRLF=windows\r\n" +
		"TRAILING=\"spaces\"   \n" +
		"export=named-export\n"
	want := map[string]string{
		"PLAIN":            "value",
		"EXPORTED":         "exported",
		"SINGLE":           `a $literal \ "quote"`,
		"DOUBLE":           "two words",
		"EMPTY":            "",
		"COMMENTED":        "value",
		"QUOTED_COMMENTED": "value",
		"HASH":             "abc#def",
		"CRLF":             "windows",
		"TRAILING":         "spaces",
		"export":           "named-export",
	}
	wanted := make(map[string]bool)
	for name := range want {
		wanted[name] = true
	}

	got, err := parseEnv([]byte(data), wanted)
	if err != nil {
		t.Fatalf("parseEnv: %v", err)
	}
	for name, value := range want {
		if got[name].value != value {
			t.Errorf("%s = %q, want %q", name, got[name].value, value)
		}
	}
	if len(got) != len(want) {
		t.Errorf("parsed %d variables, want %d", len(got), len(want))
	}
}

func TestParseEnvKeepsOnlyWantedVariables(t *testing.T) {
	data := "APP_NAME=Laravel\n" +
		"VITE_APP_NAME=\"${APP_NAME}\"\n" +
		"MAIL_FROM_NAME=${APP_NAME}\n" +
		"GREETING=hello world\n" +
		"ESCAPED=\"a\\nb\"\n" +
		"SFTPIT_PASSWORD=secret\n"

	got, err := parseEnv([]byte(data), map[string]bool{"SFTPIT_PASSWORD": true})
	if err != nil {
		t.Fatalf("parseEnv: %v", err)
	}
	if len(got) != 1 || got["SFTPIT_PASSWORD"].value != "secret" {
		t.Errorf("parseEnv = %v, want only SFTPIT_PASSWORD", got)
	}
}

func TestParseEnvRejectsUnsupportedValuesOfWantedVariables(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{"SECRET=${OTHER}", "variable expansion"},
		{`SECRET="pre$OTHER"`, "variable expansion"},
		{"SECRET=`whoami`", "command substitution"},
		{`SECRET="a\nb"`, "escape sequences"},
		{`SECRET=a\b`, "escape sequences"},
		{"SECRET=two words", "cannot contain spaces"},
		{"SECRET= leading", "cannot contain spaces"},
		{"SECRET=it's", "quotes inside"},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			_, err := parseEnv([]byte("OTHER=1\n"+tt.line+"\n"), map[string]bool{"SECRET": true})
			if err == nil {
				t.Fatal("parseEnv succeeded")
			}
			if !strings.HasPrefix(err.Error(), "2: SECRET: ") || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want line 2 and %q", err, tt.want)
			}
		})
	}
}

func TestParseEnvRejectsMalformedLinesAnywhere(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{"NO_EQUALS", "expected KEY=value"},
		{"1NAME=x", `invalid variable name "1NAME"`},
		{"NAME =x", `invalid variable name "NAME "`},
		{`NAME="unterminated`, "unterminated \" quote"},
		{"NAME='unterminated", "unterminated ' quote"},
		{"NAME='a' b", "unexpected text after the closing quote"},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			_, err := parseEnv([]byte("SECRET=x\n\n"+tt.line+"\n"), map[string]bool{"SECRET": true})
			if err == nil {
				t.Fatal("parseEnv succeeded")
			}
			if !strings.HasPrefix(err.Error(), "3: ") || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want line 3 and %q", err, tt.want)
			}
		})
	}
}

func TestParseEnvRejectsAWantedVariableSetTwice(t *testing.T) {
	_, err := parseEnv([]byte("SECRET=a\nSECRET=b\n"), map[string]bool{"SECRET": true})
	if err == nil || err.Error() != "2: SECRET is already set on line 1" {
		t.Errorf("error = %v, want the second line reported", err)
	}
	if _, err := parseEnv([]byte("OTHER=a\nOTHER=b\n"), map[string]bool{"SECRET": true}); err != nil {
		t.Errorf("a repeated variable that is not wanted: %v", err)
	}
}

func TestReadEnvFileWarnsWhenOthersCanReadIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows file modes do not describe access")
	}
	dir := t.TempDir()
	private := filepath.Join(dir, "private.env")
	shared := filepath.Join(dir, "shared.env")
	for name, mode := range map[string]os.FileMode{private: 0o600, shared: 0o644} {
		if err := os.WriteFile(name, []byte("SECRET=x\n"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(name, mode); err != nil {
			t.Fatal(err)
		}
	}

	if _, warning, err := readEnvFile(private, nil); err != nil || warning != "" {
		t.Errorf("private file: warning %q, error %v; want neither", warning, err)
	}
	_, warning, err := readEnvFile(shared, nil)
	if err != nil || !strings.Contains(warning, "readable by other users") {
		t.Errorf("shared file: warning %q, error %v; want a warning", warning, err)
	}
}

func TestReadEnvFileNamesTheFileInErrors(t *testing.T) {
	name := filepath.Join(t.TempDir(), "bad.env")
	if err := os.WriteFile(name, []byte("GOOD=1\nBAD\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := readEnvFile(name, nil)
	if err == nil || err.Error() != name+":2: expected KEY=value" {
		t.Errorf("error = %v, want %s:2: expected KEY=value", err, name)
	}
}
