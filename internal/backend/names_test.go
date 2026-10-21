package backend

import (
	"slices"
	"strings"
	"testing"
)

func TestEncodeName(t *testing.T) {
	tests := []struct{ name, encoded string }{
		{"orders.csv", "orders.csv"},
		{".hidden_file-2", ".hidden_file-2"},
		{"Orders 2026.CSV", "^orders%202026.^c^s^v"},
		{"café", "caf%c3%a9"},
		// NFD spells é as e and a combining accent, so it is another name.
		{"café", "cafe%cc%81"},
		{"100%^", "100%25%5e"},
		{`a<b>c:d"e\f|g?h*i`, "a%3cb%3ec%3ad%22e%5cf%7cg%3fh%2ai"},
		{"tab\tnewline\n", "tab%09newline%0a"},
		{"orders.csv.", "orders.csv%2e"},
		{"...", "..%2e"},
		{"trailing space ", "trailing%20space%20"},
		{"con", "%63on"},
		{"nul.txt", "%6eul.txt"},
		{"lpt9.tar.gz", "%6cpt9.tar.gz"},
		{"com0", "%63om0"},
		{"CON", "^c^o^n"},
		{"console", "console"},
		{"com10", "com10"},
		{"x\x00y", "x\x00y"},
	}
	for _, tt := range tests {
		if got := encodeName(tt.name); got != tt.encoded {
			t.Errorf("encodeName(%q) = %q, want %q", tt.name, got, tt.encoded)
		}
	}
}

func TestDecodeNameAcceptsOnlyEncodings(t *testing.T) {
	for _, name := range []string{
		"Orders.csv", // a capital is never stored as itself
		"%61",        // a is stored as itself
		"%4F",        // hex digits are lowercase
		"^O",
		"^1",
		"%2",
		"%zz",
		"%",
		"^",
		"orders.",
		"con",
		"%2e%2e",
		"a b",
	} {
		if decoded, ok := decodeName(name); ok {
			t.Errorf("decodeName(%q) = %q, want no name, since encodeName never gives it", name, decoded)
		}
	}
}

func FuzzNameEncoding(f *testing.F) {
	for _, name := range []string{"orders.csv", "Orders 2026.CSV", "café", "con.txt", "a.", "%^"} {
		f.Add(name)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if name == "" || strings.ContainsAny(name, "/\x00") {
			return
		}
		encoded := encodeName(name)
		if decoded, ok := decodeName(encoded); !ok || decoded != name {
			t.Fatalf("decodeName(%q) = %q, %v; want %q back", encoded, decoded, ok, name)
		}
		if strings.Trim(encoded, "abcdefghijklmnopqrstuvwxyz0123456789-_.%^") != "" {
			t.Errorf("encodeName(%q) = %q, which holds a byte outside the allowed set", name, encoded)
		}
		stem, _, _ := strings.Cut(encoded, ".")
		if strings.HasSuffix(encoded, ".") || slices.Contains(deviceNames, stem) {
			t.Errorf("encodeName(%q) = %q, which Windows would change or take for a device", name, encoded)
		}
	})
}
