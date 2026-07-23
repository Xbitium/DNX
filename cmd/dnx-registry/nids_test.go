package main

// Tests for the registry as namespace-identifier authority.
//
// The claims under test, in order of consequence:
//   1. identifiers survive a restart, including the never-reuse counter;
//   2. the parent/child split is airtight — a parent never allocates into a
//      delegated branch, a child allocates only beneath its granted prefix,
//      and the two together produce one consistent global numbering;
//   3. what gets published is signed, and verifiably so.

import (
	"encoding/json"
	"net"
	"sort"
	"testing"
	"time"

	"dnx/internal/nspath"
	"dnx/internal/proto"
	"dnx/internal/zone"
)

// newNIDRegistry builds a registry with allocation enabled, persisting into
// the test's temp dir so restart behaviour is exercisable.
func newNIDRegistry(t *testing.T, zoneName, zonePath, nidsFile string) *registry {
	t.Helper()
	r := &registry{names: map[string]*record{}}
	if err := r.loadOrCreateKey(""); err != nil { // ephemeral signing key
		t.Fatalf("key: %v", err)
	}
	r.zoneName = zone.Normalise(zoneName)
	s, err := loadNIDStore(nidsFile)
	if err != nil {
		t.Fatalf("nid store: %v", err)
	}
	r.nids = s
	if err := seedZonePrefix(r.nids.tree, r.zoneName, zonePath); err != nil {
		t.Fatalf("zone prefix: %v", err)
	}
	return r
}

func bindOK(t *testing.T, r *registry, name string) {
	t.Helper()
	ep := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	if res := r.bind(name, someKey, ep, time.Now()); res == bindRejected {
		t.Fatalf("bind(%s) rejected", name)
	}
	r.allocateFor(name)
}

// Registration allocates; the allocation is stable; and a sibling gets the
// next number without disturbing the first.
func TestBindAllocatesAStablePath(t *testing.T) {
	r := newNIDRegistry(t, "", "", "")
	bindOK(t, r, "host1.dnx.dnxroute.com")
	first := r.pathFor("host1.dnx.dnxroute.com")
	if first == "" {
		t.Fatal("no path allocated at bind")
	}
	bindOK(t, r, "host1.dnx.dnxroute.com") // refresh must not renumber
	if got := r.pathFor("host1.dnx.dnxroute.com"); got != first {
		t.Fatalf("refresh renumbered: %s -> %s", first, got)
	}
	bindOK(t, r, "host2.dnx.dnxroute.com")
	if a, b := r.pathFor("host1.dnx.dnxroute.com"), r.pathFor("host2.dnx.dnxroute.com"); a == b {
		t.Fatalf("two siblings share the path %s", a)
	}
}

// The whole point of persistence: a restarted registry issues the SAME
// identifiers, and never reissues one it has ever handed out.
func TestAllocationsSurviveRestart(t *testing.T) {
	file := t.TempDir() + "/nids.json"

	r1 := newNIDRegistry(t, "", "", file)
	bindOK(t, r1, "host1.dnx.dnxroute.com")
	bindOK(t, r1, "host2.dnx.dnxroute.com")
	p1 := r1.pathFor("host1.dnx.dnxroute.com")

	// "Restart": a brand-new registry over the same file.
	r2 := newNIDRegistry(t, "", "", file)
	if got := r2.pathFor("host1.dnx.dnxroute.com"); got != p1 {
		t.Fatalf("restart changed host1's path: %s -> %s", p1, got)
	}
	// A NEW sibling after restart must not collide with either survivor.
	bindOK(t, r2, "host3.dnx.dnxroute.com")
	p3 := r2.pathFor("host3.dnx.dnxroute.com")
	if p3 == p1 || p3 == r2.pathFor("host2.dnx.dnxroute.com") {
		t.Fatalf("post-restart allocation %s collides with a persisted one", p3)
	}
}

// The migration case: an ownership table that predates the allocator gets
// numbered deterministically — sorted order — so two operators migrating the
// same table mint identical identifiers.
func TestRestoredBindingsAreNumberedDeterministically(t *testing.T) {
	build := func(order []string) map[string]string {
		r := newNIDRegistry(t, "", "", "")
		for _, n := range order {
			r.names[n] = &record{PubB64: someKey, LastSeen: time.Now()}
		}
		r.allocateForRestored()
		out := map[string]string{}
		for _, n := range order {
			out[n] = r.pathFor(n)
		}
		return out
	}
	names := []string{"b.dnxroute.com", "a.dnxroute.com", "c.dnxroute.com"}
	reversed := []string{"c.dnxroute.com", "a.dnxroute.com", "b.dnxroute.com"}
	x, y := build(names), build(reversed)
	for n := range x {
		if x[n] != y[n] {
			t.Fatalf("migration is order-dependent: %s got %s vs %s", n, x[n], y[n])
		}
	}
}

// The federation split. The parent grafts the delegated prefix and never
// allocates into the branch; the child, seeded with that same prefix,
// allocates beneath it; and the union is one consistent numbering.
func TestParentAndChildProduceOneConsistentNumbering(t *testing.T) {
	// Parent: root registry for dnxroute.com, delegating eng.dnxroute.com
	// with prefix 1.1.9 (com=1, dnxroute=1, eng=9).
	parent := newNIDRegistry(t, "dnxroute.com", "", "")
	parent.delegations = []delegation{{
		Zone: "eng.dnxroute.com", Endpoint: "1.2.3.4:4400", KeyB64: someKey, Path: "1.1.9",
	}}
	if err := grantDelegationPrefixes(parent.nids.tree, parent.delegations, parent.zoneName); err != nil {
		t.Fatalf("grant: %v", err)
	}

	// Parent binds names of its own; none may land under 1.1.9.
	bindOK(t, parent, "host1.dnx.dnxroute.com")
	bindOK(t, parent, "www.dnxroute.com")
	for _, e := range parent.nids.tree.Walk() {
		if e.Name != "eng.dnxroute.com" && len(e.Path) >= 3 &&
			e.Path[0] == 1 && e.Path[1] == 1 && e.Path[2] == 9 {
			t.Fatalf("CRITICAL: parent allocated %s under the delegated prefix 1.1.9", e.Name)
		}
	}

	// A name IN the delegated branch must not be numbered by the parent.
	bindOK(t, parent, "box.eng.dnxroute.com")
	if p := parent.pathFor("box.eng.dnxroute.com"); p != "" {
		t.Fatalf("CRITICAL: parent issued %s for a name in a branch it delegated away", p)
	}

	// Child: authoritative for eng.dnxroute.com, seeded with the granted
	// prefix. Its allocations must all sit strictly beneath it.
	child := newNIDRegistry(t, "eng.dnxroute.com", "1.1.9", "")
	bindOK(t, child, "box.eng.dnxroute.com")
	p, err := nspath.Parse(child.pathFor("box.eng.dnxroute.com"))
	if err != nil {
		t.Fatalf("child path: %v", err)
	}
	if len(p) != 4 || p[0] != 1 || p[1] != 1 || p[2] != 9 {
		t.Fatalf("child allocated [%s], which is not beneath the granted prefix 1.1.9", p)
	}

	// A child cannot locally distinguish "I am the top" from "my operator
	// forgot the prefix" — enforcement is the deployment's job, and the
	// detectable symptom is DISAGREEMENT: a prefix-less child numbers the
	// branch differently from what the parent granted. Demonstrate the
	// symptom so it is on record.
	orphan := newNIDRegistry(t, "eng.dnxroute.com", "", "")
	bindOK(t, orphan, "box.eng.dnxroute.com")
	if op := orphan.pathFor("box.eng.dnxroute.com"); op == child.pathFor("box.eng.dnxroute.com") {
		t.Fatalf("expected an unprefixed child to disagree with a granted one, both said %s", op)
	}
}

// A delegations file whose prefix contradicts the persisted table must be a
// startup failure — the alternative is two branches sharing a number.
func TestDelegationPrefixConflictIsAStartupFailure(t *testing.T) {
	r := newNIDRegistry(t, "dnxroute.com", "", "")
	bindOK(t, r, "host1.dnx.dnxroute.com") // dnx takes com=1,dnxroute=1,dnx=1

	bad := []delegation{{Zone: "eng.dnxroute.com", Endpoint: "1.2.3.4:1", KeyB64: someKey,
		Path: "1.1.1"}} // 1.1.1 already names dnx.dnxroute.com
	if err := grantDelegationPrefixes(r.nids.tree, bad, r.zoneName); err == nil {
		t.Fatal("CRITICAL: a delegation prefix colliding with an existing allocation was accepted")
	}

	short := []delegation{{Zone: "eng.dnxroute.com", Endpoint: "1.2.3.4:1", KeyB64: someKey,
		Path: "7"}} // wrong depth for a three-label zone
	if err := grantDelegationPrefixes(r.nids.tree, short, r.zoneName); err == nil {
		t.Fatal("CRITICAL: a prefix shallower than its zone was accepted")
	}
}

// What RESOLVE publishes is verifiable, and tampering is detectable — the
// path is held to the same standard as the key and endpoint beside it.
func TestPublishedPathSignatureBindsThePath(t *testing.T) {
	r := newNIDRegistry(t, "", "", "")
	bindOK(t, r, "host1.dnx.dnxroute.com")

	target := "host1.dnx.dnxroute.com"
	nsp := r.pathFor(target)
	ts, nonce := time.Now().UnixMilli(), "test-nonce"
	sig := proto.SignDetached(r.signPriv, proto.NsPathBytes(target, nsp, ts, nonce))

	if err := proto.VerifyDetached(r.signPub, proto.NsPathBytes(target, nsp, ts, nonce), sig); err != nil {
		t.Fatalf("honest path failed verification: %v", err)
	}
	// Renumber one identifier and the signature must die.
	if err := proto.VerifyDetached(r.signPub, proto.NsPathBytes(target, "1.1.1.2", ts, nonce), sig); err == nil {
		t.Fatal("CRITICAL: a tampered path verified — an on-path attacker can renumber destinations")
	}
	// And a signature for one name proves nothing about another.
	if err := proto.VerifyDetached(r.signPub, proto.NsPathBytes("host2.dnx.dnxroute.com", nsp, ts, nonce), sig); err == nil {
		t.Fatal("CRITICAL: a path signature transferred between names")
	}
}

// The published table is canonical (sorted), covered by its signature, and
// includes interior zones, not only hosts.
func TestNamespaceTableIsCanonicalAndSigned(t *testing.T) {
	r := newNIDRegistry(t, "dnxroute.com", "", "")
	bindOK(t, r, "host2.dnx.dnxroute.com")
	bindOK(t, r, "host1.dnx.dnxroute.com")

	table, err := json.Marshal(r.nids.tree.Walk())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var entries []nspath.Entry
	if err := json.Unmarshal(table, &entries); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !sort.SliceIsSorted(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name }) {
		t.Fatal("published table is not sorted — two identical registries would sign different bytes")
	}
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.Name] = true
	}
	if !seen["dnx.dnxroute.com"] {
		t.Fatal("interior zone missing from the table — a router cannot route to what is not listed")
	}

	ts, nonce := time.Now().UnixMilli(), "n1"
	sig := proto.SignDetached(r.signPriv, proto.NamespaceBytes(r.zoneName, string(table), ts, nonce))
	if err := proto.VerifyDetached(r.signPub, proto.NamespaceBytes(r.zoneName, string(table), ts, nonce), sig); err != nil {
		t.Fatalf("honest table failed verification: %v", err)
	}
	tampered := string(table[:len(table)-2]) + "]}"
	if err := proto.VerifyDetached(r.signPub, proto.NamespaceBytes(r.zoneName, tampered, ts, nonce), sig); err == nil {
		t.Fatal("CRITICAL: a tampered namespace table verified")
	}
}
