package main

import (
	"os"
	"strings"
	"testing"

	"dnx/internal/zone"
)

func writeDelegations(t *testing.T, body string) string {
	t.Helper()
	p := t.TempDir() + "/delegations.json"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const someKey = "SXH3F777pd4NZXbZfP2mEiHNcaUNbultX0Sth+9l05k="

// TestDelegationCannotEscapeItsZone is the property that keeps a hierarchy a
// hierarchy. A registry may hand out branches beneath itself and nothing else
// — otherwise being given one small part of a namespace would be a route to
// taking all of it.
//
// The check runs at load time so a mistake is a startup failure rather than a
// hole nobody notices.
func TestDelegationCannotEscapeItsZone(t *testing.T) {
	cases := map[string]string{
		"its own parent":     `[{"zone":"dnxroute.com","endpoint":"1.2.3.4:4400","key":"` + someKey + `"}]`,
		"a sibling branch":   `[{"zone":"sales.dnxroute.com","endpoint":"1.2.3.4:4400","key":"` + someKey + `"}]`,
		"an unrelated zone":  `[{"zone":"example.net","endpoint":"1.2.3.4:4400","key":"` + someKey + `"}]`,
		"the top level":      `[{"zone":"com","endpoint":"1.2.3.4:4400","key":"` + someKey + `"}]`,
		"itself (a loop)":    `[{"zone":"eng.dnxroute.com","endpoint":"1.2.3.4:4400","key":"` + someKey + `"}]`,
		"a lookalike domain": `[{"zone":"evil-eng.dnxroute.com","endpoint":"1.2.3.4:4400","key":"` + someKey + `"}]`,
	}
	for label, body := range cases {
		if _, err := loadDelegations(writeDelegations(t, body), "eng.dnxroute.com"); err == nil {
			t.Fatalf("CRITICAL: delegating %s was accepted", label)
		}
	}
}

func TestLegitimateDelegationLoads(t *testing.T) {
	body := `[{"zone":"team.eng.dnxroute.com","endpoint":"1.2.3.4:4400","key":"` + someKey + `"},
	          {"zone":"lab.eng.dnxroute.com","endpoint":"5.6.7.8:4400","key":"` + someKey + `"}]`
	ds, err := loadDelegations(writeDelegations(t, body), "eng.dnxroute.com")
	if err != nil {
		t.Fatalf("a delegation beneath the zone should load: %v", err)
	}
	if len(ds) != 2 {
		t.Fatalf("expected 2 delegations, got %d", len(ds))
	}
}

// TestDelegationRequiresAUsableKey: the key is what a resolver will trust for
// that whole branch, so an unusable one is a configuration error, not
// something to discover at query time.
func TestDelegationRequiresAUsableKey(t *testing.T) {
	for label, body := range map[string]string{
		"missing key": `[{"zone":"team.eng.dnxroute.com","endpoint":"1.2.3.4:4400","key":""}]`,
		"garbage key": `[{"zone":"team.eng.dnxroute.com","endpoint":"1.2.3.4:4400","key":"not-base64!!"}]`,
		"no endpoint": `[{"zone":"team.eng.dnxroute.com","endpoint":"","key":"` + someKey + `"}]`,
	} {
		if _, err := loadDelegations(writeDelegations(t, body), "eng.dnxroute.com"); err == nil {
			t.Fatalf("%s should have been refused", label)
		}
	}
}

// TestMostSpecificDelegationWins: with nested delegations the deeper one must
// be chosen, or traffic for a sub-branch would be sent to whoever holds the
// branch above it.
func TestMostSpecificDelegationWins(t *testing.T) {
	r := &registry{
		names:    map[string]*record{},
		zoneName: "dnxroute.com",
		delegations: []delegation{
			{Zone: "eng.dnxroute.com", Endpoint: "1.1.1.1:4400", KeyB64: someKey},
			{Zone: "team.eng.dnxroute.com", Endpoint: "2.2.2.2:4400", KeyB64: someKey},
		},
	}
	d := r.delegationFor("host.team.eng.dnxroute.com")
	if d == nil || d.Zone != "team.eng.dnxroute.com" {
		t.Fatalf("the most specific delegation should win, got %v", d)
	}
	d = r.delegationFor("host.other.eng.dnxroute.com")
	if d == nil || d.Zone != "eng.dnxroute.com" {
		t.Fatalf("should fall back to the broader delegation, got %v", d)
	}
	if d := r.delegationFor("host.sales.dnxroute.com"); d != nil {
		t.Fatalf("a name in no delegated branch should have no delegation, got %v", d)
	}
}

// TestAuthorityIsCheckedBeforeAnswering: a registry asked about a name
// outside its zone must decline rather than answer. Answering would make it
// an impostor with good intentions.
func TestAuthorityIsCheckedBeforeAnswering(t *testing.T) {
	const own = "dnxroute.com"
	outside := []string{"host.example.com", "com", "evil-dnxroute.com", "dnxroute.com.attacker.net"}
	for _, n := range outside {
		if zone.Contains(own, n) {
			t.Fatalf("CRITICAL: %q was treated as inside %q", n, own)
		}
	}
	for _, n := range []string{"dnxroute.com", "host1.dnx.dnxroute.com"} {
		if !zone.Contains(own, n) {
			t.Fatalf("%q should be inside %q", n, own)
		}
	}
}

func TestNoDelegationsFileIsFine(t *testing.T) {
	ds, err := loadDelegations("", "dnxroute.com")
	if err != nil || ds != nil {
		t.Fatalf("an absent delegations file should be unremarkable: %v %v", ds, err)
	}
	ds, err = loadDelegations(t.TempDir()+"/absent.json", "dnxroute.com")
	if err != nil || ds != nil {
		t.Fatalf("a missing file should not be an error: %v %v", ds, err)
	}
}

func TestMalformedDelegationsFileIsRejected(t *testing.T) {
	if _, err := loadDelegations(writeDelegations(t, "{not json"), "dnxroute.com"); err == nil {
		t.Fatal("a malformed delegations file should be refused")
	} else if !strings.Contains(err.Error(), "delegations") {
		t.Fatalf("the error should say which file was at fault: %v", err)
	}
}
