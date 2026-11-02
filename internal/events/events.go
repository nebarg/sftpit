// Package events records what happens in a run, numbered in the order it
// happens, for the control API's timeline and facts: the run's start,
// connections and logins, each request and the reply its client got, the
// faults injected and how their waits ended, random decisions, rule changes
// and snapshots. A Recorder keeps a run's latest events in memory, bounded,
// and lets readers follow it as events arrive.
package events

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// Kind says what an Event records.
type Kind string

const (
	// RunStarted is the first event of every run, with its scenario and
	// seed in Run, and the rules it starts with in Rules.
	RunStarted Kind = "run_started"

	// Connected is a connection the server accepted, before its handshake.
	Connected Kind = "connected"

	// Authenticated is a login the server accepted.
	Authenticated Kind = "authenticated"

	// Disconnected is the end of a connection.
	Disconnected Kind = "disconnected"

	// Operation is one request and the reply its client got: Reply, and
	// BackendReply if the backend answered. Reads and writes are summed
	// into their handle's Transfer instead, unless a fault acts on one or
	// it fails. A request whose reply was never written, because a fault
	// closed the connection first, has none.
	Operation Kind = "operation"

	// Transfer sums the reads and writes through a file handle in its
	// Totals, once it is closed or its session ends.
	Transfer Kind = "transfer"

	// FaultInjected is a fault taking effect, with the Rule that chose it.
	FaultInjected Kind = "fault"

	// FaultEnded is the end of a fault's wait, a delay, stall or freeze,
	// with its Reason: "elapsed", "limit", "released", "canceled" or
	// "session_ended".
	FaultEnded Kind = "fault_ended"

	// Suppressed is a fault that its rule did not inject when its moment
	// came, with its Reason: "removed", "paused" or "max_triggers".
	Suppressed Kind = "suppressed"

	// DecisionDrawn is a random decision a rule drew from the run's seed.
	DecisionDrawn Kind = "decision"

	// RulesChanged is a change of the run's rules, with the new rules.
	RulesChanged Kind = "rules_changed"

	// Snapshotted is a snapshot of a file that a faulted handle left
	// behind.
	Snapshotted Kind = "snapshot"
)

// Event is one thing that happened in a run. Which fields are set depends
// on its Kind; the events of a connection carry its Connection and, once
// the client has logged in, its User.
type Event struct {
	// ID numbers the run's events from 1, in the order they were recorded.
	ID uint64 `json:"id"`

	// Time is when the event happened, and Elapsed how long after the
	// run's start.
	Time    time.Time `json:"time"`
	Elapsed Millis    `json:"elapsed_ms"`

	Kind Kind `json:"kind"`

	Connection     uint64 `json:"connection,omitempty"`
	User           string `json:"user,omitempty"`
	KeyFingerprint string `json:"key_fingerprint,omitempty"`

	// Request is the SFTP request an event is about, such as SSH_FXP_OPEN,
	// or connect or authenticate for a fault as a client connects or logs
	// in. RequestID is the client's ID for an SFTP request, and Path and
	// Target the canonical paths it acts on.
	Request   string  `json:"request,omitempty"`
	RequestID *uint32 `json:"request_id,omitempty"`
	Path      string  `json:"path,omitempty"`
	Target    string  `json:"target,omitempty"`

	// Reply is what the client got: a status, such as SSH_FX_OK, or the
	// type of another reply, such as SSH_FXP_HANDLE. BackendReply is what
	// the backend answered, if the request reached it. Duration is how
	// long the request took, from its arrival to its reply.
	Reply        string `json:"reply,omitempty"`
	BackendReply string `json:"backend_reply,omitempty"`
	Duration     Millis `json:"duration_ms,omitempty"`

	// Rule is the rule whose fault or decision an event records, and Fault
	// the fault.
	Rule  string `json:"rule,omitempty"`
	Fault *Fault `json:"fault,omitempty"`

	// ReadOnly is the read-only path that refused a request.
	ReadOnly string `json:"read_only,omitempty"`

	// Reason says why a fault's wait ended or a fault was suppressed, or
	// what closed the handle whose file was snapshotted: "client", "fault"
	// or "session_ended".
	Reason string `json:"reason,omitempty"`

	Transfer *Totals   `json:"transfer,omitempty"`
	Decision *Decision `json:"decision,omitempty"`
	Run      *Run      `json:"run,omitempty"`
	Rules    *Rules    `json:"rules,omitempty"`

	Snapshot *Snapshot `json:"snapshot,omitempty"`
}

// Snapshot describes a file that a faulted handle left behind: its size
// and SHA-256, and the path of its copy in the run's directory, if the run
// kept one.
type Snapshot struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Copy   string `json:"copy,omitempty"`
}

// Fault describes a fault: its Type, as rules name it, such as fail or
// partial_upload, when it acts, and its settings, such as the status of a
// fail or the cutoff of a partial upload.
type Fault struct {
	Type     string         `json:"type"`
	When     string         `json:"when,omitempty"`
	Settings map[string]any `json:"settings,omitempty"`
}

// Totals sum what went through a file handle.
type Totals struct {
	// Mode is "read", "write" or "read_write", as the handle was opened.
	Mode string `json:"mode"`

	// Reads and Writes count the requests, and BytesRead and BytesWritten
	// the bytes the backend read or stored.
	Reads        uint64 `json:"reads,omitempty"`
	BytesRead    uint64 `json:"bytes_read,omitempty"`
	Writes       uint64 `json:"writes,omitempty"`
	BytesWritten uint64 `json:"bytes_written,omitempty"`

	// End is the furthest offset a read or write reached.
	End uint64 `json:"end"`

	// Closed is "close" for a handle the client closed, or
	// "session_ended" for one still open when its session ended.
	Closed string `json:"closed"`

	// Faulted is set if a fault acted on the handle.
	Faulted bool `json:"faulted,omitempty"`
}

// Decision is a random decision a rule drew for a request, a connection or
// the run: Choice is what it decided, "probability" or the setting it drew
// a value for, such as duration or cutoff, for the Ordinal'th request the
// rule matched with the same user, path and operation. Draw is the value
// the seed gave, from 0 up to 1. A probability gives Fired, and a range
// gives Value.
type Decision struct {
	Operation   string   `json:"operation,omitempty"`
	Ordinal     uint64   `json:"ordinal,omitempty"`
	Choice      string   `json:"choice"`
	Draw        float64  `json:"draw"`
	Probability *float64 `json:"probability,omitempty"`
	Fired       *bool    `json:"fired,omitempty"`
	Value       string   `json:"value,omitempty"`
}

// Run describes the scenario a run started with.
type Run struct {
	ID       string `json:"id"`
	Scenario string `json:"scenario,omitempty"`
	Inline   bool   `json:"inline,omitempty"`
	Seed     string `json:"seed"`
	Pinned   bool   `json:"seed_pinned"`
}

// Rules describes a run's rules: their Revision, the one they replaced, if
// any, and the rules and chaos, as the control API writes them.
type Rules struct {
	Revision uint64          `json:"revision"`
	Previous uint64          `json:"previous,omitempty"`
	Faults   json.RawMessage `json:"faults"`
	Chaos    json.RawMessage `json:"chaos,omitempty"`
}

// Millis is a duration written in JSON as milliseconds, to the microsecond.
type Millis time.Duration

// MarshalJSON writes m as a number of milliseconds.
func (m Millis) MarshalJSON() ([]byte, error) {
	return strconv.AppendFloat(nil, float64(time.Duration(m).Microseconds())/1000, 'f', -1, 64), nil
}

// UnmarshalJSON reads a number of milliseconds.
func (m *Millis) UnmarshalJSON(b []byte) error {
	ms, err := strconv.ParseFloat(string(b), 64)
	if err != nil {
		return fmt.Errorf("events: a duration in milliseconds: %w", err)
	}
	*m = Millis(ms * float64(time.Millisecond))
	return nil
}
