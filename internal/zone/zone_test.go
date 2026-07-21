package zone

import "testing"

// TestLookalikeNamesAreNotContained is the trap this package exists to avoid.
//
// A plain suffix comparison reports that "evil-dnxroute.com" ends with
// "dnxroute.com", which would let anyone who registers a similar-looking name
// claim authority over a namespace that is not theirs. The boundary has to
// fall on a label.
func TestLookalikeNamesAreNotContained(t *testing.T) {
	lookalikes := []string{
		"evil-dnxroute.com",
		"notdnxroute.com",
		"xdnxroute.com",
		"dnxroute.com.attacker.net",
		"mydnxroute.com",
	}
	for _, name := range lookalikes {
		if Contains("dnxroute.com", name) {
			t.Fatalf("CRITICAL: %q was treated as part of dnxroute.com", name)
		}
		if IsNarrower(name, "dnxroute.com") {
			t.Fatalf("CRITICAL: %q was accepted as a sub-zone of dnxroute.com", name)
		}
	}
}

func TestGenuineContainment(t *testing.T) {
	in := []string{
		"dnxroute.com",
		"dnx.dnxroute.com",
		"host1.dnx.dnxroute.com",
		"a.b.c.d.dnxroute.com",
	}
	for _, name := range in {
		if !Contains("dnxroute.com", name) {
			t.Fatalf("%q should be inside dnxroute.com", name)
		}
	}
	out := []string{"dnxroute.org", "com", "example.com", "", "other.net"}
	for _, name := range out {
		if Contains("dnxroute.com", name) {
			t.Fatalf("%q should not be inside dnxroute.com", name)
		}
	}
}

// TestDelegationCannotWiden is the security property that makes federation
// safe. A registry may hand out referrals beneath itself and nowhere else.
func TestDelegationCannotWiden(t *testing.T) {
	const parent = "eng.dnxroute.com"

	allowed := []string{
		"team.eng.dnxroute.com",
		"a.b.eng.dnxroute.com",
	}
	for _, c := range allowed {
		if !IsNarrower(c, parent) {
			t.Fatalf("%q is beneath %q and should be delegable", c, parent)
		}
	}

	// Everything a compromised child might try in order to seize more than it
	// was given.
	forbidden := []string{
		"dnxroute.com",          // the parent's parent — seizing the whole namespace
		"com",                   // the top level
		"eng.dnxroute.com",      // itself: a delegation to itself is a loop
		"sales.dnxroute.com",    // a sibling branch
		"eng.dnxroute.com.evil", // superficially similar, actually elsewhere
		"unrelated.net",
		"",
	}
	for _, c := range forbidden {
		if IsNarrower(c, parent) {
			t.Fatalf("CRITICAL: %q was accepted as a delegation from %q", c, parent)
		}
	}
}

func TestCaseAndTrailingDotNormalised(t *testing.T) {
	if !Contains("DnxRoute.COM", "Host1.DNX.dnxroute.com.") {
		t.Fatal("comparison should be case-insensitive and tolerate a trailing dot")
	}
	if !IsNarrower("ENG.dnxroute.com.", "dnxroute.COM") {
		t.Fatal("narrowing check should normalise both sides")
	}
}

func TestDepthAndParent(t *testing.T) {
	cases := map[string]int{
		"com":                    1,
		"dnxroute.com":           2,
		"dnx.dnxroute.com":       3,
		"host1.dnx.dnxroute.com": 4,
		"":                       0,
	}
	for z, want := range cases {
		if got := Depth(z); got != want {
			t.Fatalf("Depth(%q) = %d, want %d", z, got, want)
		}
	}
	if Parent("host1.dnx.dnxroute.com") != "dnx.dnxroute.com" {
		t.Fatal("Parent should strip exactly one label")
	}
	if Parent("com") != "" {
		t.Fatal("the top level has no parent")
	}
}
