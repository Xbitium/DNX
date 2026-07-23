package nspath

// Tests for the authority-side additions: exact-identifier grafting,
// canonical enumeration, and persistence that keeps the never-reuse promise.

import (
	"testing"
)

// mustAllocate is a test helper.
func mustAllocate(t *testing.T, tr *Tree, name string) Path {
	t.Helper()
	p, err := tr.Allocate(name)
	if err != nil {
		t.Fatalf("Allocate(%s): %v", name, err)
	}
	return p
}

// A grafted tree must reproduce the source tree exactly, regardless of the
// order the entries arrive in. This is the property that frees consumers
// from replaying allocation history — the whole reason Graft exists.
func TestGraftReproducesAllocationsInAnyOrder(t *testing.T) {
	src := NewTree()
	mustAllocate(t, src, "host1.dnx.dnxroute.com")
	mustAllocate(t, src, "host2.dnx.dnxroute.com")
	mustAllocate(t, src, "core.gov")

	entries := src.Walk()

	// Feed the published table to a consumer BACKWARDS.
	dst := NewTree()
	for i := len(entries) - 1; i >= 0; i-- {
		if err := dst.Graft(entries[i].Name, entries[i].Path); err != nil {
			t.Fatalf("Graft(%s): %v", entries[i].Name, err)
		}
	}

	for _, e := range entries {
		got, err := dst.Resolve(e.Name)
		if err != nil {
			t.Fatalf("Resolve(%s) after graft: %v", e.Name, err)
		}
		if !got.Equal(e.Path) {
			t.Fatalf("%s: grafted tree says [%s], source says [%s]", e.Name, got, e.Path)
		}
	}
}

// A graft that contradicts an existing assignment must be refused. Both
// directions: same label with a different number, and same number on a
// different label.
func TestGraftRefusesContradictions(t *testing.T) {
	tr := NewTree()
	mustAllocate(t, tr, "host1.dnx.dnxroute.com") // com=1 dnxroute=1 dnx=1 host1=1

	// Same label, different number.
	if err := tr.Graft("host1.dnx.dnxroute.com", Path{1, 1, 1, 7}); err == nil {
		t.Fatal("CRITICAL: renumbering an existing label was accepted")
	}
	// Different label, number already spoken for.
	if err := tr.Graft("host9.dnx.dnxroute.com", Path{1, 1, 1, 1}); err == nil {
		t.Fatal("CRITICAL: one identifier was allowed to name two siblings")
	}
	// And a zero identifier is never valid on the wire or in a graft.
	if err := tr.Graft("host9.dnx.dnxroute.com", Path{1, 1, 1, 0}); err == nil {
		t.Fatal("CRITICAL: the reserved identifier 0 was accepted")
	}
}

// After grafting, the parent's counter must sit beyond the grafted numbers,
// or the very next Allocate under that parent hands out a collision.
func TestGraftAdvancesTheCounter(t *testing.T) {
	tr := NewTree()
	if err := tr.Graft("host5.dnx.dnxroute.com", Path{1, 1, 1, 5}); err != nil {
		t.Fatalf("graft: %v", err)
	}
	p := mustAllocate(t, tr, "host6.dnx.dnxroute.com")
	if p[3] <= 5 {
		t.Fatalf("CRITICAL: allocated identifier %d collides with or precedes the grafted 5", p[3])
	}
}

// Walk publishes interior names too — a zone is addressable, not only its
// leaves — and its output is sorted, which is what makes it canonical.
func TestWalkListsInteriorNamesCanonically(t *testing.T) {
	tr := NewTree()
	mustAllocate(t, tr, "host1.dnx.dnxroute.com")

	want := map[string]bool{
		"com":                    true,
		"dnxroute.com":           true,
		"dnx.dnxroute.com":       true,
		"host1.dnx.dnxroute.com": true,
	}
	entries := tr.Walk()
	if len(entries) != len(want) {
		t.Fatalf("Walk returned %d entries, want %d: %v", len(entries), len(want), entries)
	}
	for _, e := range entries {
		if !want[e.Name] {
			t.Fatalf("Walk produced unexpected name %q", e.Name)
		}
	}
	for i := 1; i < len(entries); i++ {
		if entries[i-1].Name >= entries[i].Name {
			t.Fatalf("Walk output is not sorted: %q before %q", entries[i-1].Name, entries[i].Name)
		}
	}
}

// The reason Snapshot persists counters and not merely paths: an identifier
// released before the snapshot must STILL never be reissued after a restore.
// Persisting only the live names would forget that the number ever existed,
// and the next registrant would inherit it — defect 3 in numeric form.
func TestRestoreNeverReusesAForgottenIdentifier(t *testing.T) {
	tr := NewTree()
	p1 := mustAllocate(t, tr, "host1.dnx.dnxroute.com")
	if err := tr.Forget("host1.dnx.dnxroute.com"); err != nil {
		t.Fatalf("forget: %v", err)
	}

	snap, err := tr.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	back, err := Restore(snap)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}

	p2, err := back.Allocate("hostX.dnx.dnxroute.com")
	if err != nil {
		t.Fatalf("allocate after restore: %v", err)
	}
	if p2[3] == p1[3] {
		t.Fatalf("CRITICAL: identifier %d was reissued after forget+restore — a stale forwarding entry would deliver hostX's packets to whoever held it before", p1[3])
	}
}

// The round trip must be exact: every path identical, and continued
// allocation identical to a tree that was never persisted at all.
func TestSnapshotRoundTripIsExact(t *testing.T) {
	tr := NewTree()
	names := []string{"host1.dnx.dnxroute.com", "host2.dnx.dnxroute.com", "core.gov"}
	for _, n := range names {
		mustAllocate(t, tr, n)
	}

	snap, err := tr.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	back, err := Restore(snap)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}

	for _, n := range names {
		a, _ := tr.Resolve(n)
		b, err := back.Resolve(n)
		if err != nil || !a.Equal(b) {
			t.Fatalf("%s: restored [%v] (err %v), original [%v]", n, b, err, a)
		}
	}
	// Both trees must make the SAME next choice.
	a := mustAllocate(t, tr, "host3.dnx.dnxroute.com")
	b := mustAllocate(t, back, "host3.dnx.dnxroute.com")
	if !a.Equal(b) {
		t.Fatalf("post-restore allocation diverged: original [%s], restored [%s]", a, b)
	}
}

// A snapshot whose counter contradicts its contents is a table that will
// reuse identifiers. Refusing it at load is the only safe answer.
func TestRestoreRefusesACorruptCounter(t *testing.T) {
	// host1 holds nid 3 but the parent's counter claims only 2 were issued.
	corrupt := []byte(`{"nid":0,"next":1,"children":{
	  "com":{"nid":1,"next":2,"children":{
	    "dnxroute":{"nid":1,"next":2,"children":{
	      "host1":{"nid":3,"next":1}}}}}}}`)
	if _, err := Restore(corrupt); err == nil {
		t.Fatal("CRITICAL: a snapshot that would reuse identifiers was accepted")
	}

	// And one identifier naming two siblings is equally unserviceable.
	dup := []byte(`{"nid":0,"next":1,"children":{
	  "com":{"nid":1,"next":9,"children":{
	    "a":{"nid":2,"next":1},
	    "b":{"nid":2,"next":1}}}}}`)
	if _, err := Restore(dup); err == nil {
		t.Fatal("CRITICAL: duplicate identifiers under one parent were accepted")
	}
}
