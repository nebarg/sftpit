package faults_test

import (
	"math"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/faults"
)

var testKey = faults.Key{
	Rule:       "flaky-partner",
	Activation: 1,
	Choice:     "probability",
	User:       "partner-b",
	Path:       "/incoming/orders.csv",
	Operation:  "open_write",
	Ordinal:    2,
}

func TestDrawsAreFixed(t *testing.T) {
	// These draws fix what every pinned seed reproduces. A change that alters
	// them needs a new drawVersion.
	tests := []struct {
		seed faults.Seed
		key  faults.Key
		want faults.Draw
	}{
		{seed: 481516, key: faults.Key{}, want: 0x8d06e80a9965f3f0},
		{seed: 481516, key: testKey, want: 0xa4aec35694d3cfbc},
		{seed: 7, key: testKey, want: 0xdd0cbc2f408b9736},
	}
	for _, tt := range tests {
		if got := tt.seed.Draw(tt.key); got != tt.want {
			t.Errorf("seed %d draws %#x for %+v, want %#x", tt.seed, uint64(got), tt.key, uint64(tt.want))
		}
	}
}

func TestDrawDependsOnTheSeedAndEveryPartOfTheKey(t *testing.T) {
	const seed = faults.Seed(481516)
	changed := func(change func(*faults.Key)) faults.Key {
		k := testKey
		change(&k)
		return k
	}
	tests := []struct {
		name string
		draw faults.Draw
	}{
		{"another seed", (seed + 1).Draw(testKey)},
		{"another rule", seed.Draw(changed(func(k *faults.Key) { k.Rule = "slow-partner" }))},
		{"another activation", seed.Draw(changed(func(k *faults.Key) { k.Activation++ }))},
		{"another choice", seed.Draw(changed(func(k *faults.Key) { k.Choice = "cutoff" }))},
		{"another user", seed.Draw(changed(func(k *faults.Key) { k.User = "partner-a" }))},
		{"another path", seed.Draw(changed(func(k *faults.Key) { k.Path = "/incoming/orders.part" }))},
		{"another operation", seed.Draw(changed(func(k *faults.Key) { k.Operation = "open_read" }))},
		{"another ordinal", seed.Draw(changed(func(k *faults.Key) { k.Ordinal++ }))},
		// Without lengths, these two keys would encode alike.
		{"a choice moved into the rule", seed.Draw(changed(func(k *faults.Key) { k.Rule, k.Choice = k.Rule+k.Choice, "" }))},
	}
	seen := map[faults.Draw]string{seed.Draw(testKey): "the key itself"}
	for _, tt := range tests {
		if other, ok := seen[tt.draw]; ok {
			t.Errorf("%s draws %#x, as %s does", tt.name, uint64(tt.draw), other)
		}
		seen[tt.draw] = tt.name
	}
}

func TestFires(t *testing.T) {
	tests := []struct {
		draw faults.Draw
		p    float64
		want bool
	}{
		{draw: 0, p: 0, want: false},
		{draw: 0, p: -1, want: false},
		{draw: 0, p: math.SmallestNonzeroFloat64, want: true},
		{draw: 0, p: math.NaN(), want: false},
		{draw: 1<<63 - 1, p: 0.5, want: true},
		{draw: 1 << 63, p: 0.5, want: false},
		{draw: math.MaxUint64, p: math.Nextafter(1, 0), want: false},
		{draw: math.MaxUint64, p: 1, want: true},
		{draw: math.MaxUint64, p: 2, want: true},
	}
	for _, tt := range tests {
		if got := tt.draw.Fires(tt.p); got != tt.want {
			t.Errorf("draw %#x fires at probability %v: %v, want %v", uint64(tt.draw), tt.p, got, tt.want)
		}
	}
}

func TestFiresAtItsProbability(t *testing.T) {
	const (
		seed  = faults.Seed(481516)
		n     = 100_000
		p     = 0.25
		slack = 0.005
	)
	fired := 0
	for i := range uint64(n) {
		k := testKey
		k.Ordinal = i
		if seed.Draw(k).Fires(p) {
			fired++
		}
	}
	if got := float64(fired) / n; math.Abs(got-p) > slack {
		t.Errorf("%d of %d draws fired at probability %v, a fraction of %v", fired, n, p, got)
	}
}

func TestBetweenReachesBothEnds(t *testing.T) {
	const lowest, highest = faults.Draw(0), faults.Draw(math.MaxUint64)
	unsigned := []struct{ lo, hi uint64 }{
		{0, 9},
		{5, 5},
		{1 << 20, 3 << 20},
		{math.MaxUint64 - 1, math.MaxUint64},
		{0, math.MaxUint64},
	}
	for _, r := range unsigned {
		if got := faults.Between(lowest, r.lo, r.hi); got != r.lo {
			t.Errorf("the lowest draw picks %d from [%d, %d], want %d", got, r.lo, r.hi, r.lo)
		}
		if got := faults.Between(highest, r.lo, r.hi); got != r.hi {
			t.Errorf("the highest draw picks %d from [%d, %d], want %d", got, r.lo, r.hi, r.hi)
		}
	}
	durations := []struct{ lo, hi time.Duration }{
		{100 * time.Millisecond, 2 * time.Second},
		{-time.Second, time.Second},
		{math.MinInt64, math.MaxInt64},
	}
	for _, r := range durations {
		if got := faults.Between(lowest, r.lo, r.hi); got != r.lo {
			t.Errorf("the lowest draw picks %v from [%v, %v], want %v", got, r.lo, r.hi, r.lo)
		}
		if got := faults.Between(highest, r.lo, r.hi); got != r.hi {
			t.Errorf("the highest draw picks %v from [%v, %v], want %v", got, r.lo, r.hi, r.hi)
		}
	}
}

func TestBetweenPicksEveryValueAlike(t *testing.T) {
	const (
		seed  = faults.Seed(481516)
		n     = 100_000
		slack = 0.005
	)
	var counts [10]int
	for i := range uint64(n) {
		k := testKey
		k.Choice, k.Ordinal = "cutoff", i
		counts[faults.Between(seed.Draw(k), 0, uint64(len(counts)-1))]++
	}
	want := 1 / float64(len(counts))
	for v, c := range counts {
		if got := float64(c) / n; math.Abs(got-want) > slack {
			t.Errorf("%d of %d draws picked %d from [0, %d], a fraction of %v", c, n, v, len(counts)-1, got)
		}
	}
}

func TestBetweenPanicsOnAnEmptyRange(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Between(0, 2, 1) did not panic")
		}
	}()
	faults.Between(faults.Draw(0), uint64(2), uint64(1))
}

func FuzzBetweenStaysInRange(f *testing.F) {
	f.Add(uint64(0), uint64(0), uint64(9))
	f.Add(uint64(math.MaxUint64), uint64(1)<<63, uint64(math.MaxUint64))
	f.Fuzz(func(t *testing.T, d, a, b uint64) {
		lo, hi := min(a, b), max(a, b)
		if v := faults.Between(faults.Draw(d), lo, hi); v < lo || v > hi {
			t.Errorf("draw %#x picks %d from [%d, %d]", d, v, lo, hi)
		}
		slo, shi := min(int64(a), int64(b)), max(int64(a), int64(b))
		if v := faults.Between(faults.Draw(d), slo, shi); v < slo || v > shi {
			t.Errorf("draw %#x picks %d from [%d, %d]", d, v, slo, shi)
		}
	})
}

func TestRandomSeedsFitIn32BitsAndVary(t *testing.T) {
	seen := make(map[faults.Seed]bool)
	for range 8 {
		s := faults.RandomSeed()
		if s > math.MaxUint32 {
			t.Errorf("RandomSeed() = %d, which does not fit in 32 bits", s)
		}
		seen[s] = true
	}
	// Two of eight 32-bit seeds coincide with a chance of about 1 in 150
	// million.
	if len(seen) != 8 {
		t.Errorf("eight random seeds gave %v", seen)
	}
}
