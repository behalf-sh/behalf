package diff

import (
	"math"
	"strings"
)

// Pair is one aligned position: a step from each run, or a step from one
// run and nothing from the other. Insertions and deletions are first-class
// here, not an afterthought, because the single most common reason two runs
// of the same agent stop lining up is that one of them retried.
type Pair struct {
	A *Step
	B *Step
}

// The two alignment tiers, named in Result.Aligner.
const (
	// AlignerStepKey is Q85's primary: the stored step_key, a hash of tool
	// name, normalized argument schema and causal ordinal.
	AlignerStepKey = "step_key"
	// AlignerSequence is the documented fallback: global sequence alignment
	// over a similarity score.
	AlignerSequence = "sequence"
	// AlignerBlocked is the fallback under a run long enough that the full
	// dynamic-programming matrix is refused; alignment is then decomposed on
	// unique step_key anchors and run within each block. Named separately so
	// output can be honest that a cheaper method was used.
	AlignerBlocked = "sequence (anchored)"
)

// Align pairs up the steps of two runs and reports which tier produced the
// result.
//
// # Tier 1 — step_key (Q85's primary)
//
// If every step on both sides carries a step_key, the keys are unique within
// each run, and the two key sets are equal, the pairing is by key: exact,
// O(n), and it needs no scoring at all. The bijection requirement is the
// whole guard. step_key hashes the causal ordinal, so a single inserted or
// deleted step shifts every key after it and the bijection fails — which is
// correct, because in that case a key pairing would report ~100% differences
// and the fallback reports one. A single step whose argument shape changed
// also breaks the bijection, and again the fallback is what gets it right:
// it can pair those two steps on tool name and position, which key equality
// by definition cannot.
//
// So tier 1 is used only when it explains the entire pair of runs, and
// anything less hands over to tier 2.
//
// # Tier 2 — sequence alignment (the documented fallback)
//
// Global Needleman–Wunsch over a similarity score of (tool name, argument
// shape, ordinal proximity), with step_key equality as the score's top tier
// so that wherever keys do line up the fallback reproduces tier 1's answer.
// This is deliberately not zip-by-position: a run that inserts one step at
// position 3 differs from its sibling in one step, and a positional
// comparison would call that 44 differences. Gaps in either direction are
// what make an insertion an insertion.
func Align(a, b []Step) ([]Pair, string) {
	if pairs, ok := alignByStepKey(a, b); ok {
		return pairs, AlignerStepKey
	}
	return alignBySequence(a, b)
}

// alignByStepKey is tier 1. It succeeds only on a perfect bijection of
// unique, non-empty step keys.
func alignByStepKey(a, b []Step) ([]Pair, bool) {
	if len(a) == 0 || len(a) != len(b) {
		return nil, false
	}
	byKey := make(map[string]int, len(b))
	for j := range b {
		k := b[j].StepKey
		if k == "" {
			return nil, false
		}
		if _, dup := byKey[k]; dup {
			return nil, false
		}
		byKey[k] = j
	}
	seen := make(map[string]bool, len(a))
	pairs := make([]Pair, 0, len(a))
	for i := range a {
		k := a[i].StepKey
		if k == "" || seen[k] {
			return nil, false
		}
		seen[k] = true
		j, ok := byKey[k]
		if !ok {
			return nil, false
		}
		pairs = append(pairs, Pair{A: &a[i], B: &b[j]})
	}
	return pairs, true
}

// Scoring constants for tier 2. The scale is deliberately such that a pair
// of steps with different tool names scores worse than two gaps, so the
// aligner never matches a `refund.issue` against a `tickets.close` merely
// to avoid a gap.
const (
	simSameName  = 0.60 // the dominant signal: it is the same tool
	simSameTarg  = 0.20 // ...against the same target
	simSameShape = 0.12 // ...with the same argument shape
	simProximity = 0.08 // ...at about the same point in the run
	simNamespace = 0.15 // a shared namespace is a hint, never a match

	proximityWindow = 16.0
	gapPenalty      = -0.30
)

// maxCells bounds the dynamic-programming matrix. 9M cells is ~72 MB of
// float64 and covers runs up to about 3000 steps each — larger than any
// realistic agent run; beyond it the aligner decomposes on unique step-key
// anchors first. It is a var so the anchored path can be exercised on a
// small corpus instead of on six thousand synthetic receipts.
var maxCells = 9_000_000

// similarity scores one candidate pairing in [0,1].
func similarity(a, b *Step, i, j int) float64 {
	// step_key is the primary identity (Q85). Where it agrees, nothing else
	// needs to be weighed.
	if a.StepKey != "" && a.StepKey == b.StepKey {
		return 1
	}
	if a.Operation != b.Operation {
		if ns := namespaceOf(a.Operation); ns != "" && ns == namespaceOf(b.Operation) {
			return simNamespace
		}
		return 0
	}
	s := simSameName
	if a.Target == b.Target {
		s += simSameTarg
	}
	if a.argShape == b.argShape {
		s += simSameShape
	}
	if d := math.Abs(float64(i - j)); d < proximityWindow {
		s += simProximity * (1 - d/proximityWindow)
	}
	return s
}

// score maps similarity onto the alignment scale: +1 for a certain match,
// -1 for a certain mismatch, 0 at the point where matching and not matching
// are equally good.
func score(a, b *Step, i, j int) float64 { return 2*similarity(a, b, i, j) - 1 }

// namespaceOf is the dotted prefix of a tool name: "orders.search" ->
// "orders".
func namespaceOf(name string) string {
	if i := strings.IndexByte(name, '.'); i > 0 {
		return name[:i]
	}
	return ""
}

// alignBySequence is tier 2.
func alignBySequence(a, b []Step) ([]Pair, string) {
	switch {
	case len(a) == 0 && len(b) == 0:
		return nil, AlignerSequence
	case len(a) == 0:
		return onlyOneSide(nil, b), AlignerSequence
	case len(b) == 0:
		return onlyOneSide(a, nil), AlignerSequence
	}
	if len(a)*len(b) <= maxCells {
		return needlemanWunsch(a, b), AlignerSequence
	}
	return alignAnchored(a, b), AlignerBlocked
}

func onlyOneSide(a, b []Step) []Pair {
	pairs := make([]Pair, 0, len(a)+len(b))
	for i := range a {
		pairs = append(pairs, Pair{A: &a[i]})
	}
	for j := range b {
		pairs = append(pairs, Pair{B: &b[j]})
	}
	return pairs
}

// needlemanWunsch is the classic global alignment, with ties broken toward
// the diagonal so equally good alignments prefer a match over a pair of
// gaps.
func needlemanWunsch(a, b []Step) []Pair {
	n, m := len(a), len(b)
	// dp is (n+1)x(m+1), flattened.
	dp := make([]float64, (n+1)*(m+1))
	at := func(i, j int) int { return i*(m+1) + j }
	// The edges accumulate rather than multiply, so the traceback's equality
	// checks see exactly the sums the fill produced.
	for i := 1; i <= n; i++ {
		dp[at(i, 0)] = dp[at(i-1, 0)] + gapPenalty
	}
	for j := 1; j <= m; j++ {
		dp[at(0, j)] = dp[at(0, j-1)] + gapPenalty
	}
	for i := 1; i <= n; i++ {
		for j := 1; j <= m; j++ {
			diag := dp[at(i-1, j-1)] + score(&a[i-1], &b[j-1], i-1, j-1)
			up := dp[at(i-1, j)] + gapPenalty
			left := dp[at(i, j-1)] + gapPenalty
			best := diag
			if up > best {
				best = up
			}
			if left > best {
				best = left
			}
			dp[at(i, j)] = best
		}
	}

	// Traceback, emitted back-to-front then reversed.
	var rev []Pair
	i, j := n, m
	for i > 0 || j > 0 {
		switch {
		case i > 0 && j > 0 &&
			dp[at(i, j)] == dp[at(i-1, j-1)]+score(&a[i-1], &b[j-1], i-1, j-1):
			rev = append(rev, Pair{A: &a[i-1], B: &b[j-1]})
			i--
			j--
		case i > 0 && dp[at(i, j)] == dp[at(i-1, j)]+gapPenalty:
			rev = append(rev, Pair{A: &a[i-1]})
			i--
		case j > 0:
			rev = append(rev, Pair{B: &b[j-1]})
			j--
		default:
			rev = append(rev, Pair{A: &a[i-1]})
			i--
		}
	}
	pairs := make([]Pair, 0, len(rev))
	for k := len(rev) - 1; k >= 0; k-- {
		pairs = append(pairs, rev[k])
	}
	return pairs
}

// alignAnchored is the long-run path: split both runs on step keys that
// occur exactly once in each run and in the same relative order (an anchor
// chain), then align each block between anchors on its own. This keeps the
// dynamic programming bounded without falling back to zip-by-position for
// the whole run. A block that is still too large to align is paired
// positionally with its length difference reported as insertions or
// deletions — a documented, visible degradation rather than a silent one.
func alignAnchored(a, b []Step) []Pair {
	anchorsA, anchorsB := anchorChain(a, b)
	var pairs []Pair
	prevA, prevB := 0, 0
	appendBlock := func(ea, eb int) {
		blockA, blockB := a[prevA:ea], b[prevB:eb]
		switch {
		case len(blockA) == 0 && len(blockB) == 0:
		case len(blockA)*len(blockB) <= maxCells:
			sub, _ := alignBySequence(blockA, blockB)
			pairs = append(pairs, sub...)
		default:
			pairs = append(pairs, zipPositional(blockA, blockB)...)
		}
	}
	for k := range anchorsA {
		ia, ib := anchorsA[k], anchorsB[k]
		appendBlock(ia, ib)
		pairs = append(pairs, Pair{A: &a[ia], B: &b[ib]})
		prevA, prevB = ia+1, ib+1
	}
	appendBlock(len(a), len(b))
	return pairs
}

// anchorChain returns the indices of step keys unique in both runs, kept in
// increasing order on both sides.
func anchorChain(a, b []Step) (ia, ib []int) {
	countA := map[string]int{}
	firstA := map[string]int{}
	for i := range a {
		if k := a[i].StepKey; k != "" {
			countA[k]++
			if _, ok := firstA[k]; !ok {
				firstA[k] = i
			}
		}
	}
	countB := map[string]int{}
	lastA := -1
	for j := range b {
		k := b[j].StepKey
		if k == "" {
			continue
		}
		countB[k]++
		if countB[k] > 1 || countA[k] != 1 {
			continue
		}
		i, ok := firstA[k]
		if !ok || i <= lastA {
			continue
		}
		ia = append(ia, i)
		ib = append(ib, j)
		lastA = i
	}
	return ia, ib
}

// zipPositional is the last resort inside an oversized block.
func zipPositional(a, b []Step) []Pair {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	pairs := make([]Pair, 0, len(a)+len(b)-n)
	for i := 0; i < n; i++ {
		pairs = append(pairs, Pair{A: &a[i], B: &b[i]})
	}
	for i := n; i < len(a); i++ {
		pairs = append(pairs, Pair{A: &a[i]})
	}
	for j := n; j < len(b); j++ {
		pairs = append(pairs, Pair{B: &b[j]})
	}
	return pairs
}
