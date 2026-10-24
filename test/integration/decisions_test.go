package integration

import (
	"bytes"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

// TestSeededFailuresRepeat fails a random half of OpenSSH's upload attempts
// and checks that a pinned seed fails the same attempts on every run, also
// when uploads of other files, which the same rule decides, come in between.
func TestSeededFailuresRepeat(t *testing.T) {
	sftpPath := openSSHOrSkip(t)

	const files = 12
	var alone, mixed strings.Builder
	alone.WriteString("-mkdir in\n")
	mixed.WriteString("-mkdir in\n-mkdir other\n")
	for i := range files {
		// Each file gets a second attempt, as from an application that
		// retries whether or not the first failed.
		for range 2 {
			put := fmt.Sprintf("-put orders.csv in/orders-%02d.csv\n", i)
			alone.WriteString(put)
			mixed.WriteString(put)
			fmt.Fprintf(&mixed, "-put orders.csv other/orders-%02d.csv\n-ls -l in\n", i)
		}
	}
	runs := []struct{ name, batch string }{
		{name: "first", batch: alone.String()},
		{name: "again", batch: alone.String()},
		{name: "between other uploads", batch: mixed.String()},
	}

	var first map[string][]bool
	var firstOutput string
	for _, r := range runs {
		rules, err := faults.New([]faults.Rule{{
			ID:          "random-failures",
			Match:       faults.Match{Operations: []faults.Operation{faults.OpenWrite}},
			Probability: &half,
			Action:      sftpproxy.Fail{Status: sftpwire.StatusFailure},
		}}, nil, 481516, slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatalf("faults.New: %v", err)
		}
		failures := &uploadOutcomes{faults: rules.Session(faults.Client{User: testUser}).Decide}
		srv := startServer(t, proxied, sftpproxy.Options{Faults: failures.decide})
		work := t.TempDir()
		writeFile(t, filepath.Join(work, "orders.csv"), []byte("id,total\n1,9.99\n"))

		out, err := openSSH(t, sftpPath, srv, work, r.batch)
		if err != nil {
			t.Fatalf("%s: sftp failed: %v\n%s", r.name, err, out)
		}
		decided := failures.under("/in/")
		entries, err := os.ReadDir(filepath.Join(srv.files, "in"))
		if err != nil {
			t.Fatal(err)
		}
		stored := make(map[string]bool)
		for _, e := range entries {
			stored["/in/"+e.Name()] = e.Type().IsRegular()
		}
		for name, attempts := range decided {
			if want := slices.Contains(attempts, false); stored[name] != want {
				t.Errorf("%s: %s stored: %v, but its attempts failed: %v", r.name, name, stored[name], attempts)
			}
		}
		if reported, fired := strings.Count(string(out), ": Failure"), failures.fired(); reported != fired || rules.Counts()["random-failures"].Fired != uint64(fired) {
			t.Errorf("%s: sftp reported %d failures and the rule %d, want %d:\n%s", r.name, reported, rules.Counts()["random-failures"].Fired, fired, out)
		}

		if first == nil {
			first, firstOutput = decided, string(out)
			assertSeedFailsSomeRetries(t, first, files)
			continue
		}
		if !maps.EqualFunc(decided, first, slices.Equal) {
			t.Errorf("%s: failed attempts %v, want %v as in the first run", r.name, decided, first)
		}
		if r.batch == alone.String() && string(out) != firstOutput {
			t.Errorf("%s: sftp printed\n%s\nwant, as in the first run:\n%s", r.name, out, firstOutput)
		}
	}
}

// TestSeededCutoffsRepeat cuts off a random half of OpenSSH's uploads, each
// at a random offset, and checks that a pinned seed leaves the same partial
// files on every run, and another seed different ones.
func TestSeededCutoffsRepeat(t *testing.T) {
	sftpPath := openSSHOrSkip(t)

	const files = 8
	data := randomBytes(128 << 10)
	var batch strings.Builder
	batch.WriteString("-mkdir in\n")
	for i := range files {
		fmt.Fprintf(&batch, "-put orders.csv in/orders-%d.csv\n", i)
	}
	cutoffs := faults.Range[uint64]{Min: 1000, Max: 100_000}
	stored := func(seed faults.Seed) map[string]int {
		t.Helper()
		rules, err := faults.New([]faults.Rule{{
			ID:          "random-cutoffs",
			Match:       faults.Match{Operations: []faults.Operation{faults.Write}},
			Probability: &half,
			Cutoff:      &cutoffs,
			Action:      sftpproxy.PartialUpload{Result: sftpproxy.Fail{Status: sftpwire.StatusFailure}},
		}}, nil, seed, slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatalf("faults.New: %v", err)
		}
		srv := startServerWithRules(t, rules, sftpproxy.Options{})
		work := t.TempDir()
		writeFile(t, filepath.Join(work, "orders.csv"), data)
		if out, err := openSSH(t, sftpPath, srv, work, batch.String()); err != nil {
			t.Fatalf("seed %d: sftp failed: %v\n%s", seed, err, out)
		}
		sizes := make(map[string]int)
		var cut uint64
		for i := range files {
			name := fmt.Sprintf("/in/orders-%d.csv", i)
			got, err := os.ReadFile(filepath.Join(srv.files, name))
			if err != nil {
				t.Fatal(err)
			}
			switch n := uint64(len(got)); {
			case !bytes.Equal(got, data[:len(got)]):
				t.Errorf("seed %d: %s holds %d bytes that are not the start of the upload", seed, name, n)
			case n == uint64(len(data)):
			case n < cutoffs.Min || n > cutoffs.Max:
				t.Errorf("seed %d: %s was cut off at %d, outside %+v", seed, name, n, cutoffs)
			default:
				cut++
			}
			sizes[name] = len(got)
		}
		if fired := rules.Counts()["random-cutoffs"].Fired; fired != cut {
			t.Errorf("seed %d: the rule fired %d times, but %d uploads were cut off", seed, fired, cut)
		}
		return sizes
	}

	first := stored(481516)
	cut := 0
	for _, n := range first {
		if n != len(data) {
			cut++
		}
	}
	if cut == 0 || cut == files {
		t.Fatalf("the seed cut off %d of %d uploads; the test needs some of each: %v", cut, files, first)
	}
	if again := stored(481516); !maps.Equal(again, first) {
		t.Errorf("the same seed stored %v, want %v as in the first run", again, first)
	}
	if other := stored(7); maps.Equal(other, first) {
		t.Errorf("another seed stored %v, the same as the first", other)
	}
}

// assertSeedFailsSomeRetries checks that the decisions for each of files
// paths cover both outcomes of a retry, so that the test shows something.
func assertSeedFailsSomeRetries(t *testing.T, decided map[string][]bool, files int) {
	t.Helper()
	var recovered, lost int
	for _, attempts := range decided {
		switch {
		case attempts[0] && !attempts[1]:
			recovered++
		case attempts[0] && attempts[1]:
			lost++
		}
	}
	if len(decided) != files || recovered == 0 || lost == 0 {
		t.Fatalf("the seed decides %d files, with %d recovered by their retry and %d failed twice; want %d files and some of each:\n%v",
			len(decided), recovered, lost, files, decided)
	}
}

var half = 0.5

// uploadOutcomes records, for each path, whether each upload attempt that
// faults decides fails.
type uploadOutcomes struct {
	faults func(sftpproxy.Request) sftpproxy.Action

	mu      sync.Mutex
	decided map[string][]bool
}

func (o *uploadOutcomes) decide(r sftpproxy.Request) sftpproxy.Action {
	a := o.faults(r)
	if open, ok := r.Packet.(*sftpwire.Open); ok && open.Flags&sftpwire.OpenWrite != 0 {
		o.mu.Lock()
		defer o.mu.Unlock()
		if o.decided == nil {
			o.decided = make(map[string][]bool)
		}
		o.decided[r.Path] = append(o.decided[r.Path], a != nil)
	}
	return a
}

// under returns the decisions for the paths under dir.
func (o *uploadOutcomes) under(dir string) map[string][]bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	decided := make(map[string][]bool)
	for name, attempts := range o.decided {
		if strings.HasPrefix(name, dir) {
			decided[name] = attempts
		}
	}
	return decided
}

// fired returns how many attempts have failed.
func (o *uploadOutcomes) fired() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := 0
	for _, attempts := range o.decided {
		for _, failed := range attempts {
			if failed {
				n++
			}
		}
	}
	return n
}
