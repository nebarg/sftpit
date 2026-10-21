// Package faults decides which faults to inject. Every random decision is
// drawn from the run's seed and the decision's own key, so a pinned seed
// gives the same decisions on every run of the same workload, whatever the
// timing, and no request can change the draw of another.
package faults

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"math/bits"
)

// drawVersion is part of every key. A change to how draws are made changes
// what every pinned seed reproduces, so it needs a new version.
const drawVersion = 1

// Seed fixes every random decision of a run.
type Seed uint64

// Key identifies one random decision. Each random choice a rule makes for a
// request needs its own Choice, or its draws would be the same.
type Key struct {
	// Rule is the ID of the rule that makes the decision.
	Rule string

	// Activation is the rule revision at which the rule was applied, so a
	// rule removed and applied again does not repeat its earlier pattern.
	Activation uint64

	// Choice names the random choice, such as "probability" or "cutoff".
	Choice string

	// User is the name the client logged in with.
	User string

	// Path is the canonical path the request acts on.
	Path string

	// Operation names the request, such as "open_write" or "rename".
	Operation string

	// Ordinal is the attempt or occurrence the decision is for, counted
	// within the rule's scope.
	Ordinal uint64
}

// Draw is the value a seed gives one decision, uniformly distributed over
// the uint64s.
type Draw uint64

// Draw returns the value s gives the decision k: the first 8 bytes of an
// HMAC-SHA256 of k, keyed by s. Go's own random number generators do not
// promise the same values across releases, so they cannot fix a decision.
func (s Seed) Draw(k Key) Draw {
	mac := hmac.New(sha256.New, binary.BigEndian.AppendUint64(nil, uint64(s)))
	mac.Write(k.append(nil))
	return Draw(binary.BigEndian.Uint64(mac.Sum(nil)))
}

// append encodes k so that no two keys encode alike: each string follows its
// length, and every number takes 8 bytes.
func (k Key) append(b []byte) []byte {
	b = binary.BigEndian.AppendUint64(b, drawVersion)
	b = appendString(b, k.Rule)
	b = binary.BigEndian.AppendUint64(b, k.Activation)
	b = appendString(b, k.Choice)
	b = appendString(b, k.User)
	b = appendString(b, k.Path)
	b = appendString(b, k.Operation)
	return binary.BigEndian.AppendUint64(b, k.Ordinal)
}

func appendString(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint64(b, uint64(len(s)))
	return append(b, s...)
}

// Fires reports whether a decision that fires with probability p fires for
// d. It never fires when p is 0 or less, and always fires when p is 1 or
// more.
func (d Draw) Fires(p float64) bool {
	// The top 53 bits of d, as a fraction of 2⁵³, are exact in a float64.
	return float64(d>>11)*0x1p-53 < p
}

// Between returns the value that d picks from the range [lo, hi]. The values
// are equally likely to within (hi - lo + 1) parts in 2⁶⁴. It panics if lo is
// greater than hi.
func Between[T ~int64 | ~uint64](d Draw, lo, hi T) T {
	if lo > hi {
		panic("faults: range minimum above its maximum")
	}
	// The unsigned difference is the range's width for signed T as well.
	width := uint64(hi) - uint64(lo)
	if width == math.MaxUint64 {
		return lo + T(d)
	}
	n, _ := bits.Mul64(uint64(d), width+1)
	return lo + T(n)
}
