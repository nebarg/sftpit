package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
)

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// envValue is one referenced variable read from an env file.
type envValue struct {
	value string
	line  int
}

// readEnvFile reads the env file at name and returns the values of the
// variables in wanted. Other values are never copied out of the bytes read,
// and those bytes are overwritten once parsed. It also returns a warning if
// the file is readable by other users.
func readEnvFile(name string, wanted map[string]bool) (map[string]envValue, string, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, "", err
	}
	defer clear(data)

	var warning string
	if info, err := os.Stat(name); err == nil && info.Mode().Perm()&0o044 != 0 {
		warning = fmt.Sprintf("env file %s is readable by other users (mode %v)", name, info.Mode().Perm())
	}
	values, err := parseEnv(data, wanted)
	if err != nil {
		return nil, "", fmt.Errorf("%s:%w", name, err)
	}
	return values, warning, nil
}

// envError is a parse error on one line of an env file.
type envError struct {
	line int
	msg  string
}

func (e *envError) Error() string { return fmt.Sprintf("%d: %s", e.line, e.msg) }

// parseEnv parses a strict subset of dotenv: KEY=value lines, an optional
// export prefix, single- or double-quoted values, # comments and LF or CRLF
// line endings. A line without this structure is an error wherever it is.
// Syntax that dotenv tools interpret differently, such as variable
// expansion, escapes or unquoted spaces, is an error only in a variable in
// wanted, because the others are never read.
func parseEnv(data []byte, wanted map[string]bool) (map[string]envValue, error) {
	values := make(map[string]envValue)
	for i, line := range bytes.Split(data, []byte("\n")) {
		lineNo := i + 1
		line = bytes.TrimSpace(bytes.TrimSuffix(line, []byte("\r")))
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if rest, ok := bytes.CutPrefix(line, []byte("export")); ok && len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t') {
			line = bytes.TrimLeft(rest, " \t")
		}
		keyBytes, raw, ok := bytes.Cut(line, []byte("="))
		if !ok {
			return nil, &envError{lineNo, "expected KEY=value"}
		}
		key := string(keyBytes)
		if !envNamePattern.MatchString(key) {
			return nil, &envError{lineNo, fmt.Sprintf("invalid variable name %q", key)}
		}
		value, unsupported, err := parseEnvValue(raw)
		if err != nil {
			return nil, &envError{lineNo, err.Error()}
		}
		if !wanted[key] {
			continue
		}
		if unsupported != "" {
			return nil, &envError{lineNo, key + ": " + unsupported}
		}
		if earlier, ok := values[key]; ok {
			return nil, &envError{lineNo, fmt.Sprintf("%s is already set on line %d", key, earlier.line)}
		}
		values[key] = envValue{value: string(value), line: lineNo}
	}
	return values, nil
}

// parseEnvValue parses the text after "=". A structural problem is returned
// as an error; syntax without an agreed meaning is reported as unsupported.
// The value returned shares raw's memory.
func parseEnvValue(raw []byte) (value []byte, unsupported string, err error) {
	if len(raw) == 0 {
		return nil, "", nil
	}
	if quote := raw[0]; quote == '\'' || quote == '"' {
		end := closingQuote(raw[1:], quote)
		if end < 0 {
			return nil, "", fmt.Errorf("unterminated %c quote; multi-line values are not supported", quote)
		}
		value = raw[1 : end+1]
		if rest := bytes.TrimLeft(raw[end+2:], " \t"); len(rest) > 0 && rest[0] != '#' {
			return nil, "", errors.New("unexpected text after the closing quote")
		}
		if quote == '"' {
			unsupported = unsupportedSyntax(value, "$`\\")
		}
		return value, unsupported, nil
	}

	value = raw
	if i := bytes.Index(value, []byte(" #")); i >= 0 {
		value = value[:i]
	}
	if i := bytes.Index(value, []byte("\t#")); i >= 0 {
		value = value[:i]
	}
	value = bytes.TrimRight(value, " \t")
	if bytes.ContainsAny(value, " \t") {
		return value, "unquoted values cannot contain spaces; quote the value", nil
	}
	return value, unsupportedSyntax(value, "$`\\\"'"), nil
}

// closingQuote returns the index of the first quote in s that closes the
// value, or -1. Inside double quotes, a backslash hides the next byte.
func closingQuote(s []byte, quote byte) int {
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && quote == '"':
			i++
		case s[i] == quote:
			return i
		}
	}
	return -1
}

func unsupportedSyntax(value []byte, special string) string {
	i := bytes.IndexAny(value, special)
	if i < 0 {
		return ""
	}
	switch value[i] {
	case '$':
		return "variable expansion is not supported; use single quotes for a literal $"
	case '`':
		return "command substitution is not supported; use single quotes for a literal `"
	case '\\':
		return `escape sequences are not supported; use single quotes for a literal \`
	default:
		return "quotes inside an unquoted value are not supported"
	}
}
