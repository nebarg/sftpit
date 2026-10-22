package faults

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

// Rule is one fault of a scenario: the requests it matches, which of them
// it selects and what it does to them.
type Rule struct {
	// ID names the rule in logs and counts. It must be unique within the
	// scenario.
	ID string

	// Priority orders the rules: a request gets the first rule that selects
	// it, taking lower priorities first and rules of equal priority in the
	// order given.
	Priority int

	// MaxTriggers is how many times the rule may take effect, or 0 for no
	// limit.
	MaxTriggers int

	Match Match

	// Probability, if set, is the chance that the rule fires for a request
	// it selects, drawn for each request, or for a transfer once at its
	// open. When it does not fire, the request goes to the next rule.
	Probability *float64

	// Duration, if set, is the range that a Delay draws its Duration from
	// for each request the rule fires for, in place of its own.
	Duration *Range[time.Duration]

	// Cutoff, if set, is the range that a PartialUpload draws its Cutoff
	// from for each transfer the rule selects, in place of its own.
	Cutoff *Range[uint64]

	// Action is what the rule does to a request it selects: a Delay, Fail,
	// Drop or Freeze; a PartialUpload for the write operation or a
	// CorruptDownload for the read operation, chosen when the transfer's
	// file is opened; or a WrongSize for the stat, lstat, fstat and list
	// operations. The engine sets the Reserve of a PartialUpload or
	// CorruptDownload.
	Action sftpproxy.Action
}

// Range is the values from Min to Max, inclusive, that a rule draws one of.
type Range[T ~int64 | ~uint64] struct{ Min, Max T }

func (r *Range[T]) check(field string) error {
	if r != nil && r.Min > r.Max {
		return fmt.Errorf("the %s range's min %v is above its max %v", field, r.Min, r.Max)
	}
	return nil
}

// Match says which requests a rule matches. A field left empty matches
// every request.
type Match struct {
	// User is the name the client logged in as.
	User string

	// KeyFingerprint is the SHA-256 fingerprint of the key the client logged
	// in with, as ssh-keygen prints it.
	KeyFingerprint string

	// Operations are the kinds of request the rule matches. At least one is
	// required.
	Operations []Operation

	// Path is where the request acts, which for a rename is its source.
	Path Location

	// Target is where a rename puts its file. It needs the rule to match
	// renames only.
	Target Location

	// Attempt selects transfers by their attempt at opening the file, and
	// Occurrence selects other requests by how many the rule has matched,
	// counting from 1. At most one of them is set.
	Attempt    *Attempt
	Occurrence []uint64
}

// Operation is a kind of request.
type Operation string

const (
	OpenRead  Operation = "open_read"
	OpenWrite Operation = "open_write"
	Read      Operation = "read"
	Write     Operation = "write"
	Close     Operation = "close"
	Stat      Operation = "stat"
	LStat     Operation = "lstat"
	FStat     Operation = "fstat"
	List      Operation = "list"
	Mkdir     Operation = "mkdir"
	Rmdir     Operation = "rmdir"
	Remove    Operation = "remove"
	Rename    Operation = "rename"
	SetStat   Operation = "setstat"
	RealPath  Operation = "realpath"
	StatVFS   Operation = "statvfs"

	// Any is every operation above.
	Any Operation = "any"
)

var operations = []Operation{OpenRead, OpenWrite, Read, Write, Close, Stat, LStat, FStat, List, Mkdir, Rmdir, Remove, Rename, SetStat, RealPath, StatVFS}

// listEntry is the operation of one entry of a list's reply, which only a
// WrongSize applies to.
const listEntry Operation = "list entry"

// operationOf returns the operation of r, or "" for a request that no
// operation names, which no rule matches.
func operationOf(r sftpproxy.Request) Operation {
	if r.Entry {
		return listEntry
	}
	switch p := r.Packet.(type) {
	case *sftpwire.Open:
		if p.Flags&sftpwire.OpenWrite != 0 {
			return OpenWrite
		}
		return OpenRead
	case *sftpwire.Read:
		return Read
	case *sftpwire.Write:
		return Write
	case *sftpwire.Close:
		return Close
	case *sftpwire.Stat:
		return Stat
	case *sftpwire.LStat:
		return LStat
	case *sftpwire.FStat:
		return FStat
	case *sftpwire.OpenDir, *sftpwire.ReadDir:
		return List
	case *sftpwire.Mkdir:
		return Mkdir
	case *sftpwire.Rmdir:
		return Rmdir
	case *sftpwire.Remove:
		return Remove
	case *sftpwire.Rename, *sftpwire.PosixRename:
		return Rename
	case *sftpwire.SetStat, *sftpwire.FSetStat:
		return SetStat
	case *sftpwire.RealPath:
		return RealPath
	case *sftpwire.StatVFS:
		return StatVFS
	}
	return ""
}

// Location matches canonical paths in one of five ways. The zero Location
// matches every path.
type Location struct {
	Kind LocationKind

	// Pattern is the path, directory, glob, file name or file name glob that
	// Kind matches against.
	Pattern string
}

// LocationKind is how a Location matches a path. Every match is
// case-sensitive, and in a glob, * does not match /.
type LocationKind int

const (
	// Anywhere matches every path.
	Anywhere LocationKind = iota

	// Exactly matches the path Pattern.
	Exactly

	// Under matches the directory Pattern and everything beneath it.
	Under

	// Glob matches the paths that the glob Pattern matches whole.
	Glob

	// Named matches a file named Pattern in any directory.
	Named

	// NamedGlob matches a file whose name the glob Pattern matches, in any
	// directory.
	NamedGlob
)

func (l Location) matches(p string) bool {
	switch l.Kind {
	case Exactly:
		return p == l.Pattern
	case Under:
		return p == l.Pattern || strings.HasPrefix(p, strings.TrimSuffix(l.Pattern, "/")+"/")
	case Glob:
		ok, _ := path.Match(l.Pattern, p)
		return ok
	case Named:
		return path.Base(p) == l.Pattern
	case NamedGlob:
		// The base of the empty path of an unknown handle is ".", which a
		// glob such as * would match.
		ok, _ := path.Match(l.Pattern, path.Base(p))
		return p != "" && ok
	}
	return true
}

func (l Location) check() error {
	switch l.Kind {
	case Anywhere:
		return nil
	case Exactly, Under:
		if !path.IsAbs(l.Pattern) || path.Clean(l.Pattern) != l.Pattern {
			return fmt.Errorf("%q is not a clean absolute path", l.Pattern)
		}
	case Glob:
		if !path.IsAbs(l.Pattern) {
			return fmt.Errorf("glob %q is not absolute", l.Pattern)
		}
		return checkGlob(l.Pattern)
	case Named, NamedGlob:
		if l.Pattern == "" || l.Pattern == "." || l.Pattern == ".." || strings.Contains(l.Pattern, "/") {
			return fmt.Errorf("%q is not a file name", l.Pattern)
		}
		if l.Kind == NamedGlob {
			return checkGlob(l.Pattern)
		}
	default:
		return fmt.Errorf("unknown location kind %d", l.Kind)
	}
	return nil
}

func checkGlob(pattern string) error {
	if strings.Contains(pattern, "**") {
		return fmt.Errorf("glob %q uses **, which is not supported; use a path prefix instead", pattern)
	}
	if _, err := path.Match(pattern, ""); err != nil {
		return fmt.Errorf("glob %q: %w", pattern, err)
	}
	return nil
}

// Attempt selects the transfers whose open is one of the numbered attempts
// at it. An attempt is an open of a file for the rule's transfer, whether or
// not the open succeeds. PerUser and PerPath count the attempts of each user,
// of each path, or of each user's path separately.
type Attempt struct {
	PerUser bool
	PerPath bool
	Numbers []uint64
}

// check reports a rule that the engine cannot apply as written.
func (r Rule) check() error {
	m := r.Match
	if len(m.Operations) == 0 {
		return errors.New("needs at least one operation")
	}
	for i, op := range m.Operations {
		if op != Any && !slices.Contains(operations, op) {
			return fmt.Errorf("unknown operation %q", op)
		}
		if slices.Contains(m.Operations[:i], op) {
			return fmt.Errorf("operation %q is listed twice", op)
		}
	}
	if err := m.Path.check(); err != nil {
		return fmt.Errorf("path: %w", err)
	}
	if err := m.Target.check(); err != nil {
		return fmt.Errorf("target: %w", err)
	}
	if m.Target.Kind != Anywhere && !slices.Equal(m.Operations, []Operation{Rename}) {
		return errors.New("a target needs the rule to match renames only")
	}
	if r.MaxTriggers < 0 {
		return fmt.Errorf("max_triggers is %d; it must be positive, or 0 for no limit", r.MaxTriggers)
	}
	if p := r.Probability; p != nil && !(*p >= 0 && *p <= 1) {
		return fmt.Errorf("probability %v is not from 0 to 1", *p)
	}
	if err := r.checkAction(); err != nil {
		return err
	}
	if err := r.checkRanges(); err != nil {
		return err
	}
	return r.checkSelection()
}

func (r Rule) checkAction() error {
	ops := r.Match.Operations
	switch a := r.Action.(type) {
	case sftpproxy.Delay, sftpproxy.Fail, sftpproxy.Drop, sftpproxy.Freeze:
	case sftpproxy.PartialUpload:
		if !slices.Equal(ops, []Operation{Write}) {
			return errors.New("a partial upload needs the rule to match the write operation only")
		}
		switch a.Result.(type) {
		case sftpproxy.Fail, sftpproxy.Drop, sftpproxy.Freeze:
		default:
			return fmt.Errorf("a partial upload cannot end with %T", a.Result)
		}
	case sftpproxy.CorruptDownload:
		if !slices.Equal(ops, []Operation{Read}) {
			return errors.New("a corrupt download needs the rule to match the read operation only")
		}
	case sftpproxy.WrongSize:
		for _, op := range ops {
			if !slices.Contains([]Operation{Stat, LStat, FStat, List}, op) {
				return fmt.Errorf("a wrong size applies to stat, lstat, fstat and list, not %s", op)
			}
		}
	default:
		return fmt.Errorf("unsupported action %T", r.Action)
	}
	return nil
}

func (r Rule) checkRanges() error {
	if _, ok := r.Action.(sftpproxy.Delay); r.Duration != nil && !ok {
		return errors.New("a duration range needs a delay")
	}
	if _, ok := r.Action.(sftpproxy.PartialUpload); r.Cutoff != nil && !ok {
		return errors.New("a cutoff range needs a partial upload")
	}
	if err := r.Duration.check("duration"); err != nil {
		return err
	}
	return r.Cutoff.check("cutoff_offset")
}

func (r Rule) checkSelection() error {
	m := r.Match
	switch {
	case m.Attempt != nil && m.Occurrence != nil:
		return errors.New("attempt and occurrence cannot both be set")
	case m.Attempt != nil:
		if !r.isTransfer() && slices.ContainsFunc(m.Operations, func(op Operation) bool { return op != OpenRead && op != OpenWrite }) {
			return errors.New("attempts count opens, so they need a transfer or the open_read and open_write operations; use occurrence for other operations")
		}
		return checkNumbers("attempt", m.Attempt.Numbers)
	case m.Occurrence != nil:
		return checkNumbers("occurrence", m.Occurrence)
	}
	return nil
}

func checkNumbers(name string, numbers []uint64) error {
	if len(numbers) == 0 {
		return fmt.Errorf("%s needs at least one number", name)
	}
	for i, n := range numbers {
		if n == 0 {
			return fmt.Errorf("%s numbers count from 1", name)
		}
		if slices.Contains(numbers[:i], n) {
			return fmt.Errorf("%s %d is listed twice", name, n)
		}
	}
	return nil
}

// isTransfer reports whether the rule's action applies to a transfer, and
// so is chosen when the file is opened.
func (r Rule) isTransfer() bool {
	switch r.Action.(type) {
	case sftpproxy.PartialUpload, sftpproxy.CorruptDownload:
		return true
	}
	return false
}

// selectedAt returns the operations whose requests the rule is decided at:
// the open of a transfer, the entries of a list for a WrongSize, and
// otherwise the requests of its operations.
func (r Rule) selectedAt() []Operation {
	switch r.Action.(type) {
	case sftpproxy.PartialUpload:
		return []Operation{OpenWrite}
	case sftpproxy.CorruptDownload:
		return []Operation{OpenRead}
	}
	var ops []Operation
	for _, op := range r.Match.Operations {
		switch {
		case op == Any:
			ops = append(ops, operations...)
		case op == List && r.isWrongSize():
			ops = append(ops, listEntry)
		default:
			ops = append(ops, op)
		}
	}
	return ops
}

func (r Rule) isWrongSize() bool {
	_, ok := r.Action.(sftpproxy.WrongSize)
	return ok
}
