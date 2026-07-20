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
