package dnxaddr

import "testing"

// TestSubdomainOnlyWhenPresent guards a bug found while reimplementing the
// address rule for the browser playground: at three labels, labels[n-3] is
// labels[0] — the host — so a name with no subdomain copied its host label
// into the subdomain field.
func TestSubdomainOnlyWhenPresent(t *testing.T) {
	reg := NewRegistry()

	noSub, err := reg.FromName("host1.dnxroute.com")
	if err != nil {
		t.Fatal(err)
	}
	if noSub.Field[Subdomain] != 0 {
		t.Fatalf("a name with no subdomain must have a zero subdomain field, got 0x%016x",
			noSub.Field[Subdomain])
	}
	if noSub.Field[Host] == 0 {
		t.Fatal("host field should still be populated")
	}

	withSub, err := reg.FromName("host1.dnx.dnxroute.com")
	if err != nil {
		t.Fatal(err)
	}
	if withSub.Field[Subdomain] == 0 {
		t.Fatal("a name with a subdomain must populate the subdomain field")
	}
	if withSub.Field[Subdomain] == withSub.Field[Host] {
		t.Fatal("subdomain and host must not collapse to the same value")
	}
	// The host field must be identical whether or not a subdomain exists.
	if withSub.Field[Host] != noSub.Field[Host] {
		t.Fatal("host field should depend only on the host label")
	}
}

// TestDeployedAddressUnchanged pins the address used by the live routing
// demonstration, so a change to the derivation cannot silently break it.
func TestDeployedAddressUnchanged(t *testing.T) {
	reg := NewRegistry()
	a, err := reg.FromName("host1.dnx.dnxroute.com")
	if err != nil {
		t.Fatal(err)
	}
	const want = "0000000100000000:0000000000001001:27753dd64fccf1c0:c0365b5a3867cc38"
	if got := a.String(); got != want {
		t.Fatalf("live demo address changed\n got %s\nwant %s", got, want)
	}
}

// TestUnallocatedTLDIsRejected: the assigned tiers must come from the
// registry, not be invented.
func TestUnallocatedTLDIsRejected(t *testing.T) {
	reg := NewRegistry()
	if _, err := reg.FromName("host.example.nosuchtld"); err == nil {
		t.Fatal("an unallocated TLD should be refused")
	}
	if _, err := reg.FromName("host.unallocateddomain.com"); err == nil {
		t.Fatal("an unallocated domain should be refused")
	}
}

// TestDeepNamesAreRefusedNotCollided is defect 10, found by asking whether
// node1.accounting.us.east.company.com would work.
//
// The fixed address has four fields, and a deeper name used to fall through
// the encoder with its middle labels simply dropped — so two DISTINCT names
// differing only in those labels produced one identical address, no error
// anywhere. Packets for either delivered to whichever registered first, and
// nothing on any wire could tell them apart. An encoder must refuse what it
// cannot represent; answering a smaller question than it was asked, with a
// success code, is defect 9's failure shape rebuilt in an encoder (and the
// silent-truncation family that defect 5 came from).
func TestDeepNamesAreRefusedNotCollided(t *testing.T) {
	reg := NewRegistry()

	// The pair that demonstrated the collision on live code: identical in
	// every label the four fields can see, distinct in the ones they can't.
	a, errA := reg.FromName("node1.accounting.us.dnx.dnxroute.com")
	b, errB := reg.FromName("node1.payroll.eu.dnx.dnxroute.com")

	if errA == nil || errB == nil {
		if a == b {
			t.Fatalf("CRITICAL: two distinct 6-label names silently share the address %s", a)
		}
		t.Fatal("CRITICAL: a name deeper than the format's four tiers was encoded at all")
	}

	// Exactly four labels remains the format's job, and must keep working.
	if _, err := reg.FromName("host1.dnx.dnxroute.com"); err != nil {
		t.Fatalf("a four-label name must still encode: %v", err)
	}
	// Five is already one too many — the boundary itself, not just six.
	if _, err := reg.FromName("x.y.dnx.dnxroute.com"); err == nil {
		t.Fatal("CRITICAL: a five-label name was encoded by a four-tier format")
	}
}
