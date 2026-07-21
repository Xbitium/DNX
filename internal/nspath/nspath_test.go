package nspath

import (
	"errors"
	"strings"
	"testing"
)

// TestDepthIsNotFixed is the whole point of DNXP-0001: the previous address
// held exactly four levels, and real organisation charts are not four levels.
func TestDepthIsNotFixed(t *testing.T) {
	tr := NewTree()
	names := []string{
		"host.dnxroute.com",                             // 3
		"host1.dnx.dnxroute.com",                        // 4
		"api.production.us-east.customer.com",           // 5 — did not fit before
		"vpn.engineering.floor3.buildingA.dnxroute.com", // 6 — did not fit before
		"a.b.c.d.e.f.g.h.dnxroute.com",                  // 10
	}
	for _, n := range names {
		p, err := tr.Allocate(n)
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		want := len(splitName(n))
		if p.Depth() != want {
			t.Fatalf("%s: depth %d, want %d", n, p.Depth(), want)
		}
		back, err := tr.Reverse(p)
		if err != nil || back != strings.ToLower(n) {
			t.Fatalf("%s did not survive a round trip: got %q err=%v", n, back, err)
		}
	}
}

// TestIdentifiersAreParentScoped: siblings must differ, but two different
// parents may hand out the same number. That is what keeps identifiers small
// and lets every namespace allocate locally without central coordination.
func TestIdentifiersAreParentScoped(t *testing.T) {
	tr := NewTree()
	a, _ := tr.Allocate("host1.dnx.dnxroute.com")
	b, _ := tr.Allocate("host2.dnx.dnxroute.com")

	if a[len(a)-1] == b[len(b)-1] {
		t.Fatal("siblings must not share an identifier")
	}
	// Everything above the leaf is shared, because it is the same branch.
	if !a[:len(a)-1].Equal(b[:len(b)-1]) {
		t.Fatal("siblings should share their ancestry")
	}

	// A leaf under a different parent may legitimately reuse a number.
	c, _ := tr.Allocate("host1.other.dnxroute.com")
	if c[len(c)-1] != a[len(a)-1] {
		t.Log("note: first leaf under each parent gets the same number, as intended")
	}
	// The paths as a whole must still differ.
	if a.Equal(c) {
		t.Fatal("CRITICAL: two distinct names resolved to the same path")
	}
}

// TestIdentifiersAreNeverReused guards the open question the proposal raised.
// Reuse would mean a packet in flight, or a stale forwarding entry, could be
// delivered to whatever inherited the number.
func TestIdentifiersAreNeverReused(t *testing.T) {
	tr := NewTree()
	first, _ := tr.Allocate("gone.dnx.dnxroute.com")
	if err := tr.Forget("gone.dnx.dnxroute.com"); err != nil {
		t.Fatal(err)
	}
	second, err := tr.Allocate("fresh.dnx.dnxroute.com")
	if err != nil {
		t.Fatal(err)
	}
	if first.Equal(second) {
		t.Fatal("CRITICAL: a released identifier was handed to a different name")
	}

	// And the forgotten name really is gone.
	if _, err := tr.Resolve("gone.dnx.dnxroute.com"); !errors.Is(err, ErrNotAllocated) {
		t.Fatal("a forgotten name should no longer resolve")
	}
}

// TestAllocationIsStable: allocating a sibling must not disturb a path
// already in use, or live routes would silently change under traffic.
func TestAllocationIsStable(t *testing.T) {
	tr := NewTree()
	before, _ := tr.Allocate("host1.dnx.dnxroute.com")

	for _, n := range []string{"host2.dnx.dnxroute.com", "other.dnx.dnxroute.com", "x.y.dnxroute.com"} {
		if _, err := tr.Allocate(n); err != nil {
			t.Fatal(err)
		}
	}
	after, err := tr.Resolve("host1.dnx.dnxroute.com")
	if err != nil {
		t.Fatal(err)
	}
	if !before.Equal(after) {
		t.Fatalf("CRITICAL: an existing path changed when siblings were added: %v -> %v", before, after)
	}
}

func TestWireRoundTrip(t *testing.T) {
	tr := NewTree()
	p, _ := tr.Allocate("api.production.us-east.customer.com")

	b, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Equal(got) {
		t.Fatalf("round trip changed the path: %v -> %v", p, got)
	}
}

// TestWireIsSmallerThanTheFixedAddress: the old address was 32 bytes at every
// depth. The replacement is smaller for anything shallower than eight levels,
// and unlike the old one it does not simply fail past four.
func TestWireIsSmallerThanTheFixedAddress(t *testing.T) {
	const fixed = 32
	cases := []struct{ depth, want int }{
		{3, 13}, {4, 17}, {5, 21}, {8, 33}, {16, 65},
	}
	for _, c := range cases {
		if got := EncodedLen(c.depth); got != c.want {
			t.Fatalf("depth %d: %d bytes, want %d", c.depth, got, c.want)
		}
	}
	if EncodedLen(4) >= fixed {
		t.Fatal("the common case should be smaller than the fixed address it replaces")
	}
	t.Logf("4 levels: %d bytes vs %d fixed; 8 levels: %d bytes vs impossible",
		EncodedLen(4), fixed, EncodedLen(8))
}

// TestMalformedWireIsRefused: a truncated path must never be half-interpreted.
// Guessing at a destination is how a packet ends up somewhere nobody intended.
func TestMalformedWireIsRefused(t *testing.T) {
	tr := NewTree()
	p, _ := tr.Allocate("host1.dnx.dnxroute.com")
	good, _ := p.Encode()

	for name, b := range map[string][]byte{
		"empty":        {},
		"zero levels":  {0},
		"truncated":    good[:len(good)-2],
		"header only":  {4},
		"absurd depth": {200, 1, 2, 3, 4},
	} {
		if _, err := Decode(b); err == nil {
			t.Fatalf("%s should have been refused", name)
		}
	}
	// The good one still decodes, so the checks are not simply refusing all.
	if _, err := Decode(good); err != nil {
		t.Fatalf("a valid path was refused: %v", err)
	}
}

func TestDepthLimitEnforced(t *testing.T) {
	tr := NewTree()
	deep := strings.Repeat("a.", MaxDepth+1) + "com"
	if _, err := tr.Allocate(deep); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("a name past the depth limit should be refused, got %v", err)
	}
	p := make(Path, MaxDepth+1)
	if _, err := p.Encode(); !errors.Is(err, ErrTooDeep) {
		t.Fatal("encoding past the depth limit should be refused")
	}
}

// TestReverseExplainsAMisroute is the diagnosability question from the
// proposal. With only numbers on the wire, an operator staring at a
// misdelivered packet needs a way to ask what it was actually addressed to.
func TestReverseExplainsAMisroute(t *testing.T) {
	tr := NewTree()
	tr.Allocate("host1.dnx.dnxroute.com")
	tr.Allocate("host2.dnx.dnxroute.com")

	captured, _ := tr.Resolve("host2.dnx.dnxroute.com")
	name, err := tr.Reverse(captured)
	if err != nil {
		t.Fatal(err)
	}
	if name != "host2.dnx.dnxroute.com" {
		t.Fatalf("reverse resolution gave %q", name)
	}

	// A path containing an identifier nobody allocated must be reported as
	// unknown rather than guessed at.
	if _, err := tr.Reverse(Path{1, 1, 1, 9999}); !errors.Is(err, ErrNotAllocated) {
		t.Fatal("an unallocated identifier should not resolve to a name")
	}
}

// TestCaseAndWhitespaceNormalised: two spellings of the same name must not
// become two different destinations.
func TestCaseAndWhitespaceNormalised(t *testing.T) {
	tr := NewTree()
	a, _ := tr.Allocate("Host1.DNX.DnxRoute.com")
	b, err := tr.Resolve(" host1.dnx.dnxroute.com ")
	if err != nil {
		t.Fatal(err)
	}
	if !a.Equal(b) {
		t.Fatal("CRITICAL: capitalisation produced a different destination")
	}
}
