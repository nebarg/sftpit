package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/faults"
)

// TestLaravelConsumerAcknowledgementDenied has a Laravel application poll
// outgoing, processing each file and then deleting it, with its first
// delete denied, and checks what each of its consumers processes.
// Flysystem's SFTP adapter ignores a failed delete, so neither consumer
// learns of the denial: the naive one processes the file again on its next
// poll, and the idempotent one only deletes it again.
func TestLaravelConsumerAcknowledgementDenied(t *testing.T) {
	t.Parallel()
	php := phpseclibOrSkip(t)

	seed := t.TempDir()
	data := randomBytes(64<<10 + 321)
	if err := os.Mkdir(filepath.Join(seed, "outgoing"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(seed, "outgoing", "orders.csv"), data)
	const file = "outgoing/orders.csv"
	processed := strconv.Itoa(len(data)) + " " + digest(data)
	tests := []struct {
		consumer string
		// again is what the consumer does with the file on its second poll.
		again string
	}{
		{"naive", "process"},
		{"idempotent", "skip"},
	}
	for _, tt := range tests {
		t.Run(tt.consumer, func(t *testing.T) {
			t.Parallel()
			opts := scenarioOptions(t, `  deny-ack:
    faults:
      - id: deny-ack
        deny_acknowledgement: {path_glob: /outgoing/*.csv, occurrences: [1]}
`, "deny-ack")
			var logs capturedLog
			opts.Logger = logs.logger()
			opts.SeedDir = seed
			_, srv := startRuns(t, opts)

			transcript := runPhpseclib(t, php, srv, "consume.php", t.TempDir(), tt.consumer, "3")
			srv.waitForSessions()

			want := []line{
				step(t, "poll 1 list", []string{file}),
				step(t, "poll 1 process "+file, processed),
				step(t, "poll 1 delete "+file, true),
				step(t, "poll 2 list", []string{file}),
				step(t, "poll 2 "+tt.again+" "+file, processed),
				step(t, "poll 2 delete "+file, true),
				step(t, "poll 3 list", []string{}),
			}
			if got, want := lines(transcript), lines(want); got != want {
				t.Errorf("consume.php printed\n%swant\n%s", got, want)
			}
			assertHolds(t, srv, "/"+file, nil)
			if got, want := srv.counts(t, "deny-ack"), (faults.Counts{Matched: 2, Selected: 1, Fired: 1}); got != want {
				t.Errorf("counts = %+v, want both deletes matched and the first denied", got)
			}
			if fired := `msg="rule fired" rule=deny-ack operation=remove path=/` + file + ` user=` + testUser + ` ordinal=1`; !strings.Contains(logs.text(), fired) {
				t.Errorf("logs lack %s:\n%s", fired, logs.text())
			}
		})
	}
}

// step returns the line of JSON that a Laravel script prints for the
// outcome of one step.
func step(t testing.TB, op string, result any) line {
	t.Helper()
	out, err := json.Marshal(map[string]any{"op": op, "result": result})
	if err != nil {
		t.Fatal(err)
	}
	return line(out)
}
