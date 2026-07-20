package main

import (
	"net"
	"testing"
	"time"
)

func newTestRegistry() *registry { return &registry{names: map[string]*record{}} }

func addr(t *testing.T, s string) *net.UDPAddr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

const (
	ownerKey    = "OWNER_ed25519_public_key_base64"
	attackerKey = "ATTACKER_ed25519_public_key_base64"
	theName     = "host1.dnx.dnxroute.com"
)

// TestFirstClaimWins is the base rule: the first key to claim a name owns it,
// and a different key is refused even with a perfectly valid signature.
func TestFirstClaimWins(t *testing.T) {
	r := newTestRegistry()
	now := time.Now()

	if got := r.bind(theName, ownerKey, addr(t, "203.0.113.7:4400"), now); got != bindNew {
		t.Fatalf("first claim should bind, got %v", got)
	}
	if got := r.bind(theName, attackerKey, addr(t, "198.51.100.9:4400"), now); got != bindRejected {
		t.Fatalf("CRITICAL: a different key claimed an owned name (got %v)", got)
	}
	if got := r.bind(theName, ownerKey, addr(t, "203.0.113.7:5000"), now); got != bindRefreshed {
		t.Fatalf("owner re-registering should refresh, got %v", got)
	}
}

// TestOwnershipSurvivesBeingOffline is the regression test for the bug this
// file exists to fix.
//
// The registry used to delete the whole record after ten minutes without a
// heartbeat. That made a name available to anyone the moment its owner was
// switched off for long enough — and when the owner came back it was refused
// its own name, because the name now belonged to somebody else's key.
//
// Close your laptop over lunch, lose your identity. Ownership must not be a
// function of uptime.
func TestOwnershipSurvivesBeingOffline(t *testing.T) {
	r := newTestRegistry()
	start := time.Now()

	if got := r.bind(theName, ownerKey, addr(t, "203.0.113.7:4400"), start); got != bindNew {
		t.Fatalf("setup: expected bindNew, got %v", got)
	}

	// The owner goes quiet for well beyond the old ten-minute prune window.
	later := start.Add(45 * time.Minute)
	offline, retired := r.prune(later)
	if offline != 1 {
		t.Fatalf("endpoint should have been marked offline, got %d", offline)
	}
	if retired != 0 {
		t.Fatalf("CRITICAL: binding was retired after only 45 minutes (retired=%d)", retired)
	}

	// An attacker tries to take the now-quiet name.
	if got := r.bind(theName, attackerKey, addr(t, "198.51.100.9:4400"), later); got != bindRejected {
		t.Fatalf("CRITICAL: name was hijacked while its owner was offline (got %v)", got)
	}

	// The rightful owner comes back and must be accepted.
	if got := r.bind(theName, ownerKey, addr(t, "203.0.113.7:6001"), later); got != bindRefreshed {
		t.Fatalf("CRITICAL: owner was refused its own name after returning (got %v)", got)
	}
	if ep := r.names[theName].Endpoint; ep == nil || ep.Port != 6001 {
		t.Fatalf("returning owner should have refreshed its endpoint, got %v", ep)
	}
}

// TestPinnedToTheOldPruneWindow checks the exact boundary that used to fail,
// so a future change to the constants cannot quietly reintroduce the bug.
func TestPinnedToTheOldPruneWindow(t *testing.T) {
	r := newTestRegistry()
	start := time.Now()
	r.bind(theName, ownerKey, addr(t, "203.0.113.7:4400"), start)

	oldPruneWindow := 10 * staleAfter // the value that used to delete the record
	at := start.Add(oldPruneWindow + time.Minute)
	r.prune(at)

	if _, still := r.names[theName]; !still {
		t.Fatal("CRITICAL: binding vanished at the old ten-minute prune window")
	}
	if got := r.bind(theName, attackerKey, addr(t, "198.51.100.9:4400"), at); got != bindRejected {
		t.Fatalf("CRITICAL: name claimable at the old prune window (got %v)", got)
	}
}

// TestEndpointExpiresEvenThoughBindingDoesNot: liveness still has to expire,
// otherwise the registry would hand out a stale address for a machine that
// has moved or gone away.
func TestEndpointExpiresEvenThoughBindingDoesNot(t *testing.T) {
	r := newTestRegistry()
	start := time.Now()
	r.bind(theName, ownerKey, addr(t, "203.0.113.7:4400"), start)

	// Still fresh a moment later.
	r.prune(start.Add(staleAfter / 2))
	if r.names[theName].Endpoint == nil {
		t.Fatal("endpoint expired too early")
	}

	// Past the freshness window the location is forgotten...
	r.prune(start.Add(staleAfter + time.Second))
	rec := r.names[theName]
	if rec.Endpoint != nil {
		t.Fatal("stale endpoint should have been cleared")
	}
	// ...but the ownership record is untouched.
	if rec.PubB64 != ownerKey {
		t.Fatal("CRITICAL: clearing the endpoint disturbed the key binding")
	}
}

// TestRetirementIsDeliberate documents that bindings do eventually expire,
// but only after a period chosen as policy rather than as a side effect.
func TestRetirementIsDeliberate(t *testing.T) {
	r := newTestRegistry()
	start := time.Now()
	r.bind(theName, ownerKey, addr(t, "203.0.113.7:4400"), start)

	_, retired := r.prune(start.Add(bindingRetention + time.Hour))
	if retired != 1 {
		t.Fatalf("binding should retire after %s, got retired=%d", bindingRetention, retired)
	}
	if _, still := r.names[theName]; still {
		t.Fatal("retired binding should be gone")
	}
	if bindingRetention < 30*24*time.Hour {
		t.Fatalf("retention of %s is too short to be safe for an offline machine", bindingRetention)
	}
}

// TestDistinctNamesAreIndependent guards against a table-wide mistake in prune.
func TestDistinctNamesAreIndependent(t *testing.T) {
	r := newTestRegistry()
	start := time.Now()
	r.bind("a.dnx.dnxroute.com", ownerKey, addr(t, "203.0.113.7:4400"), start)
	r.bind("b.dnx.dnxroute.com", attackerKey, addr(t, "198.51.100.9:4400"), start.Add(time.Hour))

	r.prune(start.Add(time.Hour + time.Second))
	if r.names["a.dnx.dnxroute.com"].Endpoint != nil {
		t.Fatal("a should be offline")
	}
	if r.names["b.dnx.dnxroute.com"].Endpoint == nil {
		t.Fatal("b was still fresh and should not have been marked offline")
	}
}
