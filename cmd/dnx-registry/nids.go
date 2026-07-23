package main

// The registry as namespace-identifier authority (DNXP-0001).
//
// Identifiers were the one thing this system still distributed by hand: every
// router carried the same ordered name list in its config and re-derived the
// numbers locally, which worked exactly as long as no two configs ever
// disagreed — and disagreed silently when they did. Section 10.3 records that
// hazard. This file removes its cause.
//
// The design observation is that the machinery already existed. A registry
// already OWNS the namespace: it persists which key owns which name, and it
// delegates whole branches to child registries. Parent-scoped identifier
// allocation is that same hierarchy wearing numbers — so the registry
// allocates a path when it binds a name, persists the allocation beside the
// ownership it already persists, and publishes it two ways:
//
//   - each RESOLVE_RESP carries the target's path, under its own signature
//     (see the version-skew note on Message.NsPath);
//   - a NAMESPACE query returns the whole table, signed, which is what a
//     router fetches instead of deriving numbers from config order.
//
// Federation: a child registry's names live UNDER a prefix the parent
// assigned when it delegated the zone. That prefix travels in the delegation
// config — the same file, and the same out-of-band trust operation, that
// already carries the child's endpoint and signing key. Distribution of leaf
// identifiers is automatic; distribution of zone prefixes rides the channel
// delegation already trusted.

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"

	"dnx/internal/nspath"
	"dnx/internal/zone"
)

// nidStore couples a Tree to the file that keeps it honest across restarts.
type nidStore struct {
	tree *nspath.Tree
	path string // empty disables persistence (tests)
}

// loadNIDStore restores the allocation table, or starts an empty one on
// first boot. A corrupt table is a startup failure, not a shrug: serving
// wrong identifiers misroutes everything that trusts them, and the operator
// is the only party who can decide which backup to believe.
func loadNIDStore(path string) (*nidStore, error) {
	s := &nidStore{tree: nspath.NewTree(), path: path}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil // first boot
	}
	if err != nil {
		return nil, err
	}
	t, err := nspath.Restore(b)
	if err != nil {
		return nil, fmt.Errorf("refusing to start with a namespace table that cannot be trusted: %w", err)
	}
	s.tree = t
	return s, nil
}

// save persists the allocation table atomically, for the same reason the
// ownership table is written the same way: a truncated table would not look
// broken, it would look empty, and empty is the most dangerous thing an
// allocator can look — the next allocation would start from 1 and hand out
// every number the old table had already promised to someone else.
func (s *nidStore) save() error {
	if s.path == "" {
		return nil
	}
	b, err := s.tree.Snapshot()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// seedZonePrefix grafts this registry's own position in the global namespace
// into its tree, from a dotted prefix like "1.1.3" for a zone like
// "eng.dnxroute.com" (root-most first: com=1, dnxroute=1, eng=3).
//
// The prefix is given, not derived, because a DELEGATED registry must not
// number its own ancestors — those levels belong to the parent, and two
// registries independently numbering "com" would disagree the moment their
// tables met. The parent chose the prefix when it delegated the zone, wrote
// it into its delegations file, and the child operator copies it once,
// exactly as they already copy the endpoint and key the delegation trusts.
//
// An empty prefix is legal and means this registry is the TOP of its
// hierarchy: nobody delegated its zone, so there is nobody to have numbered
// its ancestors, and it numbers itself through ordinary allocation. A
// registry cannot tell "I am the top" from "my operator forgot the prefix"
// — both look like an empty flag — so this is one of the facts that rides
// the delegation handshake: whoever hands a zone away hands the prefix with
// it, and a child configured without one is a deployment error the parent's
// published table will expose (its numbers for the branch will not match).
func seedZonePrefix(t *nspath.Tree, zoneName, dotted string) error {
	if dotted == "" {
		return nil // top of the hierarchy: self-numbering
	}
	if zoneName == "" {
		return fmt.Errorf("--zone-path given without --zone")
	}
	p, err := nspath.Parse(dotted)
	if err != nil {
		return fmt.Errorf("--zone-path %q: %w", dotted, err)
	}
	if got, want := len(p), zone.Depth(zoneName); got != want {
		return fmt.Errorf("--zone-path %q has %d levels but zone %q has %d labels", dotted, got, zoneName, want)
	}
	if err := t.Graft(zoneName, p); err != nil {
		return fmt.Errorf("zone prefix %q for %q contradicts the persisted table: %w", dotted, zoneName, err)
	}
	return nil
}

// allocateFor assigns (or looks up) the path for a freshly bound name and
// persists the result. Allocation happens at BIND time because binding is
// the moment the registry decides a name exists — the identifier is part of
// what existence means here.
//
// A save failure is logged loudly rather than failing the registration: the
// binding itself is already durable, and the allocation will be re-made
// identically on the next save because the in-memory tree still holds it.
// What must never happen silently is the process restarting between a lost
// save and the next successful one — hence the volume of the log line.
func (r *registry) allocateFor(name string) {
	if r.nids == nil {
		return
	}
	// Only number names this registry is actually authoritative for. The
	// ownership table can hold out-of-zone names (REGISTER predates zones
	// and does not police them), but issuing identifiers for a branch that
	// belongs to someone else would be two authorities numbering one
	// namespace — the exact disagreement this whole mechanism exists to end.
	if r.zoneName != "" && !zone.Contains(r.zoneName, name) {
		return
	}
	// Never allocate INTO a branch that has been delegated away: the child
	// registry is the allocator there, and the prefix graft only reserves
	// the zone node itself, not what grows beneath it.
	if d := r.delegationFor(name); d != nil {
		return
	}
	p, err := r.nids.tree.Allocate(name)
	if err != nil {
		log.Printf("WARNING: no namespace path for %s: %v", name, err)
		return
	}
	if err := r.nids.save(); err != nil {
		log.Printf("WARNING: namespace table NOT PERSISTED after allocating %s -> [%s]: %v — a restart before the next successful save would forget this allocation", name, p, err)
	}
}

// allocateForRestored numbers every restored binding that predates the
// allocator, in sorted-name order so the migration is deterministic: two
// operators restoring the same ownership table mint the same identifiers.
// It runs once; after it, the persisted identifier table is the authority
// and order never matters again.
func (r *registry) allocateForRestored() {
	r.mu.Lock()
	names := make([]string, 0, len(r.names))
	for n := range r.names {
		names = append(names, n)
	}
	r.mu.Unlock()
	sort.Strings(names)
	for _, n := range names {
		r.allocateFor(n)
	}
}

// pathFor returns the dotted path for a name, or "" if none was allocated.
func (r *registry) pathFor(name string) string {
	if r.nids == nil {
		return ""
	}
	p, err := r.nids.tree.Resolve(name)
	if err != nil {
		return ""
	}
	return p.String()
}

// grantDelegationPrefixes reserves, in this registry's own tree, the prefix
// each delegation file entry assigns to its child zone. Grafting them at
// load means the parent can never later Allocate a number that collides
// with a branch it handed away, and a delegations file whose prefixes
// contradict the persisted table — or each other — is a startup failure
// instead of two registries quietly numbering the same branch differently.
func grantDelegationPrefixes(t *nspath.Tree, ds []delegation, ownZone string) error {
	for _, d := range ds {
		if d.Path == "" {
			continue // legacy entry: delegation without identifier assignment
		}
		p, err := nspath.Parse(d.Path)
		if err != nil {
			return fmt.Errorf("delegation of %q: path %q: %w", d.Zone, d.Path, err)
		}
		// The prefix must be as deep as the zone name itself — one
		// identifier per label from the global root — or the child would be
		// numbering levels the prefix never covered.
		if got, want := len(p), zone.Depth(d.Zone); got != want {
			return fmt.Errorf("delegation of %q: path %q has %d levels but the zone has %d labels",
				d.Zone, d.Path, got, want)
		}
		if err := t.Graft(d.Zone, p); err != nil {
			return fmt.Errorf("delegation of %q: %w", d.Zone, err)
		}
	}
	return nil
}
