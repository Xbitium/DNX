// Package zone implements the containment rules that make delegation safe.
//
// A referral is a delegation of trust: one registry telling a resolver to
// believe another registry about some part of the namespace. Everything
// dangerous about federation lives in deciding whether a particular referral
// is allowed, so those decisions are gathered here rather than spread through
// the message handlers.
package zone

import "strings"

// Normalise puts a name in the form the comparisons expect: lower case, no
// surrounding whitespace, no trailing dot.
func Normalise(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// Contains reports whether name lies within zone — either the zone itself or
// something beneath it.
//
// The comparison is label-wise, and that matters more than it looks. A plain
// suffix test says "evil-dnxroute.com" ends with "dnxroute.com" and would
// hand an attacker authority over a namespace they merely chose a similar
// name for. The boundary must fall on a dot.
func Contains(zoneName, name string) bool {
	z, n := Normalise(zoneName), Normalise(name)
	if z == "" || n == "" {
		return false
	}
	if n == z {
		return true
	}
	return strings.HasSuffix(n, "."+z)
}

// IsNarrower reports whether child is strictly beneath parent.
//
// This is the rule that stops a delegation from widening. A registry
// authoritative for eng.example.com may hand out referrals inside its own
// branch; it must never be able to issue one for example.com, for a sibling
// branch, or for an unrelated namespace — otherwise delegating a small part
// of a namespace would hand over the whole of it, and any compromised child
// zone would become a way to seize the root.
func IsNarrower(child, parent string) bool {
	c, p := Normalise(child), Normalise(parent)
	if c == "" || p == "" || c == p {
		return false
	}
	return strings.HasSuffix(c, "."+p)
}

// Depth is the number of labels in a zone, used to bound how far a chain of
// referrals may descend.
func Depth(zoneName string) int {
	z := Normalise(zoneName)
	if z == "" {
		return 0
	}
	return strings.Count(z, ".") + 1
}

// Parent returns the zone one level up, or "" at the top.
func Parent(zoneName string) string {
	z := Normalise(zoneName)
	if i := strings.Index(z, "."); i >= 0 {
		return z[i+1:]
	}
	return ""
}
