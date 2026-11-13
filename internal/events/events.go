// Package events records what happens in a run, numbered in the order it
// happens, for the activity the API serves: the run's start, connections
// and logins, each request and the reply its client got, the faults
// injected and how their waits ended, random decisions and rule changes. A
// Recorder keeps a run's latest events in memory, bounded.
package events

import (
	"fmt"
	"strconv"
	"time"
)

// Kind says what an Event records.
type Kind string

const (
	// RunStarted is the first event of every run, with its seed in Run,
	// and the revision of the rules it starts with in Rules.
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
	// with its Reason: Elapsed, AtLimit, Released, Canceled or
	// SessionEnded.
	FaultEnded Kind = "fault_ended"

	// Suppressed is a fault that its rule did not inject when its moment
	// came, with its Reason: RuleRemoved or MaxTriggers.
	Suppressed Kind = "suppressed"

	// DecisionDrawn is a random decision a rule drew from the run's seed.
	DecisionDrawn Kind = "decision"

	// RulesChanged is a change of the run's rules, with their revision.
	RulesChanged Kind = "rules_changed"
)

// FaultType names a kind of fault, as an event's Fault gives it.
type FaultType string

// The faults an event can name.
const (
	DelayFault            FaultType = "delay"
	StallFault            FaultType = "stall"
	FailFault             FaultType = "fail"
	CloseConnectionFault  FaultType = "close_connection"
	FreezeConnectionFault FaultType = "freeze_connection"
	CloseSubsystemFault   FaultType = "close_subsystem"
	ListenerDownFault     FaultType = "listener_down"
	HideFault             FaultType = "hide"
	WrongSizeFault        FaultType = "wrong_size"
	PartialDownloadFault  FaultType = "partial_download"
	CorruptDownloadFault  FaultType = "corrupt_download"
	CorruptUploadFault    FaultType = "corrupt_upload"
)

// Waits reports whether a fault of type t holds a request, a reply or a
// connection, and so ends with a FaultEnded event.
func (t FaultType) Waits() bool {
	return t == DelayFault || t == StallFault || t == FreezeConnectionFault
}

// Reason says why a fault's wait ended or a fault was suppressed.
type Reason string

const (
	// Elapsed ends a delay that lasted as long as it was set to.
	Elapsed Reason = "elapsed"

	// AtLimit ends a stall or freeze that nothing released.
	AtLimit Reason = "limit"

	// Canceled ends a wait whose rule was removed or switched off.
	Canceled Reason = "canceled"

	// Released ends a stall or freeze that was released by hand.
	Released Reason = "released"

	// SessionEnded ends a wait whose session or connection ended first.
	SessionEnded Reason = "session_ended"

	// RuleRemoved suppresses a fault whose rule was removed before its
	// moment came.
	RuleRemoved Reason = "removed"

	// MaxTriggers suppresses a fault whose rule had already fired as often
	// as it may.
	MaxTriggers Reason = "max_triggers"
)

// Closed says how a file handle ended.
type Closed string

const (
	// ClosedByClient is a handle its client closed.
	ClosedByClient Closed = "close"

	// ClosedBySession is a handle still open when its session ended.
	ClosedBySession Closed = "session_ended"
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

	// Remote is the address a connection came from, and Client the
	// version its client announced as it logged in.
	Remote string `json:"remote,omitempty"`
	Client string `json:"client,omitempty"`

	// Request is the SFTP request an event is about, such as SSH_FXP_OPEN,
	// or connect or authenticate for a fault as a client connects or logs
	// in. RequestID is the client's ID for an SFTP request, and Path and
	// Target the canonical paths it acts on.
	Request   string  `json:"request,omitempty"`
	RequestID *uint32 `json:"request_id,omitempty"`
	Path      string  `json:"path,omitempty"`
	Target    string  `json:"target,omitempty"`

	// Mode is how an SSH_FXP_OPEN asked for its file: "read", "write" or
	// "read_write".
	Mode string `json:"mode,omitempty"`

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

	// Reason says why a fault's wait ended or a fault was suppressed.
	Reason Reason `json:"reason,omitempty"`

	Transfer *Totals   `json:"transfer,omitempty"`
	Decision *Decision `json:"decision,omitempty"`
	Run      *Run      `json:"run,omitempty"`
	Rules    *Rules    `json:"rules,omitempty"`
}

// Fault describes a fault: its Type, when it acts, and its settings, such as
// the status of a fail or the cutoff of a partial upload.
type Fault struct {
	Type     FaultType      `json:"type"`
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

	Closed Closed `json:"closed"`

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

// Run describes a run as it starts.
type Run struct {
	ID   string `json:"id"`
	Seed string `json:"seed"`
}

// Rules describes a change of a run's rules: their Revision, and the one
// they replaced, if any.
type Rules struct {
	Revision uint64 `json:"revision"`
	Previous uint64 `json:"previous,omitempty"`
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
