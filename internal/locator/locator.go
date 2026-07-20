// Package locator implements DNX name-hierarchical routing:
// ordered tier paths and the longest-suffix forwarding logic that
// replaces IP's longest-prefix match.
//
// THE ONE IDEA: a locator is an ordered list of tiers, most-significant
// FIRST (big -> small), the opposite of a DNS name. A router matches the
// coarsest tier it is responsible for, forwards, and forgets the rest.
// Aggregation falls out for free: a core router holds one entry per region,
// not one per host.
//
//	human FQDN:  host1.disa.dnxroute.com      (small -> big, for people)
//	locator:     dnx / us-east / gov / disa / host1   (big -> small, for routers)
package locator

import (
	"strings"
)

// Locator is an ordered tier path, index 0 = most significant (root side).
//
//	Loc{"dnx","us-east","gov","disa","host1"}
//	     ^root                          ^leaf
type Locator []string

// Parse turns a slash- or dot-delimited locator string into tiers.
// Accepts "dnx/us-east/gov/disa/host1" or "dnx.us-east.gov.disa.host1".
func Parse(s string) Locator {
	s = strings.TrimSpace(s)
	sep := "/"
	if !strings.Contains(s, "/") {
		sep = "."
	}
	var out Locator
	for _, t := range strings.Split(s, sep) {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// String renders a locator big->small with slashes (router-facing form).
func (l Locator) String() string { return strings.Join(l, "/") }

// Tier returns the tier at a given depth (0 = root), or "" if out of range.
func (l Locator) Tier(depth int) string {
	if depth < 0 || depth >= len(l) {
		return ""
	}
	return l[depth]
}

// Depth is the number of tiers.
func (l Locator) Depth() int { return len(l) }

// ---------------------------------------------------------------------------
// Forwarding table (the DNX FIB analogue)
// ---------------------------------------------------------------------------

// Special next-hop sentinels.
const (
	HopLocal   = ":local"   // the leaf lives here — deliver, don't forward
	HopDefault = ":default" // no tier match — send toward root (default route)
)

// Table maps a single tier value to a next-hop name, for ONE router.
// The router that owns region "us-east" has entries keyed by the NEXT
// tier down (gov, edu, ...). Table size = number of distinct children at
// this router = O(children), NOT O(hosts). That is the whole scaling claim.
type Table struct {
	tierDepth int               // which tier index THIS router resolves (0=root,1=region,...)
	entries   map[string]string // tier value -> next hop
	def       string            // default hop (toward root) if no entry matches
}

// NewTable builds a forwarding table for a router that resolves `tierDepth`.
func NewTable(tierDepth int) *Table {
	return &Table{
		tierDepth: tierDepth,
		entries:   map[string]string{},
		def:       HopDefault,
	}
}

// Add installs a route: "traffic whose tier[tierDepth] == value goes to hop".
func (t *Table) Add(tierValue, hop string) { t.entries[tierValue] = hop }

// SetDefault overrides the default (toward-root) next hop.
func (t *Table) SetDefault(hop string) { t.def = hop }

// Size is the number of forwarding entries — the aggregation metric we report.
func (t *Table) Size() int { return len(t.entries) }

// TierDepth is the tier index this router is responsible for.
func (t *Table) TierDepth() int { return t.tierDepth }

// Entries returns a copy of the routes (for inspection / the aggregation table).
func (t *Table) Entries() map[string]string {
	c := make(map[string]string, len(t.entries))
	for k, v := range t.entries {
		c[k] = v
	}
	return c
}

// Decision is the result of a single forwarding lookup — carries the *reason*
// so the PoC can prove routers decide on ONE tier, never the whole name.
type Decision struct {
	MatchedTier  string // the tier value this router matched on
	MatchedDepth int    // its depth in the locator
	NextHop      string // where the packet goes next (or HopLocal)
	Reason       string // human-readable "why", for the forwarding trace
}

// Lookup performs one hop of longest-suffix forwarding for a locator.
//
// It reads EXACTLY ONE tier — the one at this router's tierDepth — and
// decides. It never reads tiers above (already resolved by upstream) or
// below (someone else's job), and never touches an IP. This is the
// method that embodies §3 of the concept doc.
func (t *Table) Lookup(loc Locator) Decision {
	tier := loc.Tier(t.tierDepth)

	// Are we the router that owns the leaf? The leaf is the last tier;
	// if the tier we resolve IS the last tier and we have a local route
	// for it, deliver.
	isLeafDepth := t.tierDepth == loc.Depth()-1

	if tier == "" {
		return Decision{
			MatchedDepth: t.tierDepth,
			NextHop:      t.def,
			Reason:       "no tier at this depth; default route toward root",
		}
	}

	hop, ok := t.entries[tier]
	if !ok {
		return Decision{
			MatchedTier:  tier,
			MatchedDepth: t.tierDepth,
			NextHop:      t.def,
			Reason:       "tier '" + tier + "' unknown here; default route toward root",
		}
	}

	if hop == HopLocal || isLeafDepth && hop == HopLocal {
		return Decision{
			MatchedTier:  tier,
			MatchedDepth: t.tierDepth,
			NextHop:      HopLocal,
			Reason:       "leaf '" + tier + "' is local; deliver",
		}
	}

	return Decision{
		MatchedTier:  tier,
		MatchedDepth: t.tierDepth,
		NextHop:      hop,
		Reason:       "matched tier '" + tier + "' -> " + hop + " (ignored " + suffixNote(loc, t.tierDepth) + ")",
	}
}

// suffixNote describes which tiers this router deliberately did NOT read —
// evidence for the whitepaper that each hop consumes only its own tier.
func suffixNote(loc Locator, depth int) string {
	var below []string
	for i := depth + 1; i < loc.Depth(); i++ {
		below = append(below, loc[i])
	}
	if len(below) == 0 {
		return "nothing below"
	}
	return strings.Join(below, "/")
}
