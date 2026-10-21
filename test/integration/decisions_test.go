package integration

import (
	"fmt"
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

// TestSeededFailuresRepeat fails a seeded half of OpenSSH's upload attempts
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
		failures := &seededFailures{seed: 481516, p: 0.5}
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
		if reported, fired := strings.Count(string(out), ": Failure"), failures.fired(); reported != fired {
			t.Errorf("%s: sftp reported %d failures, want %d:\n%s", r.name, reported, fired, out)
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

// seededFailures fails each upload attempt with probability p, drawn from
// seed, counting each path's attempts as the rule engine will.
type seededFailures struct {
	seed faults.Seed
	p    float64

	mu sync.Mutex
	// decided holds, for each path, whether each of its attempts failed.
	decided map[string][]bool
}

func (f *seededFailures) decide(r sftpproxy.Request) sftpproxy.Action {
	open, ok := r.Packet.(*sftpwire.Open)
	if !ok || open.Flags&sftpwire.OpenWrite == 0 {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.decided == nil {
		f.decided = make(map[string][]bool)
	}
	attempts := f.decided[r.Path]
	draw := f.seed.Draw(faults.Key{
		Rule:      "random-failures",
		Choice:    "probability",
		User:      testUser,
		Path:      r.Path,
		Operation: "open_write",
		Ordinal:   uint64(len(attempts)) + 1,
	})
	fail := draw.Fires(f.p)
	f.decided[r.Path] = append(attempts, fail)
	if fail {
		return sftpproxy.Fail{Status: sftpwire.StatusFailure}
	}
	return nil
}

// under returns the decisions for the paths under dir.
func (f *seededFailures) under(dir string) map[string][]bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	decided := make(map[string][]bool)
	for name, attempts := range f.decided {
		if strings.HasPrefix(name, dir) {
			decided[name] = attempts
		}
	}
	return decided
}

// fired returns how many attempts have failed.
func (f *seededFailures) fired() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, attempts := range f.decided {
		for _, failed := range attempts {
			if failed {
				n++
			}
		}
	}
	return n
}
