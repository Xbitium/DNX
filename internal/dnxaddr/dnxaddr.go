// Package dnxaddr implements the DNX 256-bit structured address:
// four 64-bit fields derived from the name hierarchy.
//
//	[ 64 bits TLD ][ 64 bits domain ][ 64 bits subdomain ][ 64 bits host ]
//	    255..192       191..128          127..64              63..0
//
// WHY 256 FIXED BITS INSTEAD OF THE TEXT NAME:
// Routers never string-match. They mask to a field and compare 64-bit
// integers — the SAME fixed-width operation IP silicon already does at
// line rate, just wider and semantically structured. This is what makes
// name-hierarchical routing hardware-plausible.
//
// HYBRID ALLOCATION (the committed model):
//   - TLD (field 0) and domain (field 1) are REGISTRY-ASSIGNED. Deliberate
//     numbers give geographic aggregation: a numbering authority hands
//     adjacent regions adjacent values, so cores aggregate.
//   - subdomain (field 2) and host (field 3) are HASH-DERIVED:
//     truncate(SHA-256(label)) -> 64 bits. Zero authority, zero friction —
//     you name your own hosts. Aggregation isn't needed this deep (the
//     owning site router enumerates its own leaves anyway).
//
// This mirrors the internet's own split: administered top (IANA/RIR
// prefixes), self-service bottom (you name your hosts).
package dnxaddr

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
)

// Addr is a DNX 256-bit address as four 64-bit fields, most-significant first.
//
//	Field[0] = TLD, Field[1] = domain, Field[2] = subdomain, Field[3] = host
type Addr struct {
	Field [4]uint64
}

// Field indices, named for clarity.
const (
	TLD = iota
	Domain
	Subdomain
	Host
)

// FieldName labels a field index for human output.
func FieldName(i int) string {
	switch i {
	case TLD:
		return "TLD"
	case Domain:
		return "domain"
	case Subdomain:
		return "subdomain"
	case Host:
		return "host"
	}
	return "?"
}

// Registry is the DNX numbering authority for the ASSIGNED tiers (TLD,
// domain). In production this is a delegated, replicated allocation service
// (the IANA-of-DNX). Here it is an in-memory map, which is all the PoC needs
// to demonstrate that assignment — not hashing — is what yields aggregation.
type Registry struct {
	tld    map[string]uint64 // ".com" -> assigned 64-bit block
	domain map[string]uint64 // "dnxroute" -> assigned 64-bit value
}

// NewRegistry seeds an allocation authority. Note how the ASSIGNED values are
// deliberate and grouped — that deliberateness is exactly what hashing can't
// give you, and exactly what makes cores aggregate.
func NewRegistry() *Registry {
	return &Registry{
		tld: map[string]uint64{
			// Top tier blocks. Deliberately spaced so related TLDs can share
			// a core route via masking (e.g. all gov-adjacent under one range).
			"com": 0x0000_0001_0000_0000,
			"gov": 0x0000_0002_0000_0000,
			"mil": 0x0000_0003_0000_0000,
			"org": 0x0000_0004_0000_0000,
			"edu": 0x0000_0005_0000_0000,
		},
		domain: map[string]uint64{
			"dnxroute": 0x0000_0000_0000_1001,
			"disa":     0x0000_0000_0000_2001,
			"dod":      0x0000_0000_0000_2002,
		},
	}
}

// AssignTLD / AssignDomain let the PoC add allocations.
func (r *Registry) AssignTLD(label string, v uint64)    { r.tld[label] = v }
func (r *Registry) AssignDomain(label string, v uint64) { r.domain[label] = v }

// hash64 derives a 64-bit field from a label: truncate(SHA-256(label)).
// Used for the self-service tiers (subdomain, host).
func hash64(label string) uint64 {
	sum := sha256.Sum256([]byte(strings.ToLower(label)))
	return binary.BigEndian.Uint64(sum[:8])
}

// FromName maps a human FQDN to its 256-bit DNX address using the hybrid rule.
//
//	"host1.disa.dnxroute.com"
//	 host   sub    domain  TLD     (DNS order: small -> big)
//
// We read the FQDN right-to-left into fields TLD, domain, subdomain, host.
// TLD and domain come from the registry (assigned); subdomain and host are
// hashed. Missing tiers are zero (e.g. a name with no subdomain).
func (r *Registry) FromName(fqdn string) (Addr, error) {
	labels := splitFQDN(fqdn) // small -> big
	if len(labels) < 2 {
		return Addr{}, fmt.Errorf("name %q needs at least domain.tld", fqdn)
	}
	// Reverse into big -> small so index aligns with fields.
	n := len(labels)
	tldLabel := labels[n-1]
	domainLabel := labels[n-2]

	var a Addr

	// --- assigned tiers ---
	tv, ok := r.tld[tldLabel]
	if !ok {
		return Addr{}, fmt.Errorf("TLD %q is not allocated by the DNX registry", tldLabel)
	}
	a.Field[TLD] = tv

	dv, ok := r.domain[domainLabel]
	if !ok {
		return Addr{}, fmt.Errorf("domain %q is not allocated under .%s", domainLabel, tldLabel)
	}
	a.Field[Domain] = dv

	// --- hashed tiers (self-service) ---
	// Anything between host and domain is subdomain; the first label is host.
	// A name with only domain.tld has no subdomain, and its subdomain field
	// stays zero. The guard is n >= 4, not n >= 3: at n == 3 the expression
	// labels[n-3] is labels[0], which is the HOST label, so a three-label
	// name silently copied its host into its subdomain field.
	if n >= 4 {
		a.Field[Subdomain] = hash64(labels[n-3]) // the label just below domain
	}
	a.Field[Host] = hash64(labels[0]) // the leftmost label is the host

	return a, nil
}

// splitFQDN returns dot-separated labels, small->big, trimming empties.
func splitFQDN(fqdn string) []string {
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(fqdn), ".") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Fixed-width forwarding operations — the whole point
// ---------------------------------------------------------------------------

// FieldAt returns the 64-bit value a router at tier `depth` matches on.
// depth 0 = TLD (core), 3 = host (leaf). This is the ONLY read a router does.
func (a Addr) FieldAt(depth int) uint64 {
	if depth < 0 || depth > 3 {
		return 0
	}
	return a.Field[depth]
}

// String renders the address as four hex fields, big->small.
func (a Addr) String() string {
	return fmt.Sprintf("%016x:%016x:%016x:%016x",
		a.Field[TLD], a.Field[Domain], a.Field[Subdomain], a.Field[Host])
}

// Pretty renders the address with tier labels for the forwarding trace.
func (a Addr) Pretty() string {
	return fmt.Sprintf("TLD=%016x domain=%016x sub=%016x host=%016x",
		a.Field[TLD], a.Field[Domain], a.Field[Subdomain], a.Field[Host])
}

// Bytes serializes the 256-bit address to 32 bytes (wire form).
func (a Addr) Bytes() []byte {
	b := make([]byte, 32)
	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint64(b[i*8:], a.Field[i])
	}
	return b
}
