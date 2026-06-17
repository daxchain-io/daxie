package ens

import "strings"

// normalize applies the minimal, ENSIP-15-adjacent input normalization daxie v1
// performs before hashing a name (design §8 T5 / plan §1): it lowercases ASCII
// and validates the dot structure, returning the normalized name plus an
// `ascii` flag the caller surfaces as a NON-FATAL warning when the name contains
// non-ASCII bytes.
//
// What it does (the conservative, deterministic subset):
//   - trims a single trailing dot (the FQDN root form "vitalik.eth." ≡
//     "vitalik.eth"); the bare root "." normalizes to "" (the root node).
//   - lowercases ASCII A–Z (ENS names are case-insensitive over ASCII; the
//     reverse-node hex is likewise lowercase — see reverseNode).
//   - rejects empty labels (a leading dot, a trailing dot beyond the one
//     stripped, or "a..b") with ok=false, because namehash of an empty label is a
//     silent footgun (it would hash keccak("") into the node and resolve to an
//     attacker-controllable sibling). A genuinely empty input is the root and is
//     allowed (ok=true, "").
//
// What it deliberately does NOT do in v1 (so we never SILENTLY transform a name
// into a different one): full UTS-46 / ENSIP-15 Unicode normalization,
// punycode/IDNA, or confusable folding. A name carrying non-ASCII bytes is passed
// through UNCHANGED (only ASCII case-folded) and flagged via ascii=false so the
// caller can warn "this name was not Unicode-normalized; verify the resolved
// address" rather than guess. This is fail-loud-not-wrong: we would rather surface
// a warning than normalize a homoglyph name into the wrong node.
//
// normalize is pure: no network, no state.
func normalize(name string) (out string, ascii bool, ok bool) {
	// A single trailing dot is the FQDN root marker; strip exactly one.
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		// The root node. Valid, ASCII, no labels to check.
		return "", true, true
	}

	asciiOnly := true
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A')) // ASCII case-fold
		default:
			if r > 0x7F {
				asciiOnly = false
			}
			b.WriteRune(r)
		}
	}
	out = b.String()

	// Reject any empty label (leading dot, interior "..", etc.). An empty label
	// is never a valid ENS name and would hash to an attacker-influenceable node.
	for _, label := range strings.Split(out, ".") {
		if label == "" {
			return out, asciiOnly, false
		}
	}
	return out, asciiOnly, true
}
