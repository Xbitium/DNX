package main

import (
	"net"
	"os"
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

// TestOwnershipSurvivesRestart is the regression test for the second half of
// the same bug.
//
// Separating ownership from liveness kept a name safe while its machine was
// switched off — but the table lived only in memory, so restarting the
// registry un-owned every name in existence. Deploying a fix would itself
// have handed the whole namespace to whoever registered first afterwards.
func TestOwnershipSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	state := dir + "/registry.json"
	start := time.Now()

	// --- first process ---
	r1 := &registry{names: map[string]*record{}, statePath: state}
	if got := r1.bind(theName, ownerKey, addr(t, "203.0.113.7:4400"), start); got != bindNew {
		t.Fatalf("setup: %v", got)
	}
	if err := r1.save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	// --- process restarts: brand new in-memory state ---
	r2 := &registry{names: map[string]*record{}, statePath: state}
	n, err := r2.load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 restored binding, got %d", n)
	}

	// The attacker tries to claim the name the moment the registry comes back.
	if got := r2.bind(theName, attackerKey, addr(t, "198.51.100.9:4400"), start); got != bindRejected {
		t.Fatalf("CRITICAL: name was claimable after a registry restart (got %v)", got)
	}
	// The owner reconnects and is recognised.
	if got := r2.bind(theName, ownerKey, addr(t, "203.0.113.7:7000"), start); got != bindRefreshed {
		t.Fatalf("CRITICAL: owner not recognised after restart (got %v)", got)
	}

	// Endpoints are liveness and must NOT be restored from disk — a restored
	// endpoint could send traffic to a machine that has since moved.
	r3 := &registry{names: map[string]*record{}, statePath: state}
	r3.load()
	if r3.names[theName].Endpoint != nil {
		t.Fatal("endpoint should not be persisted; it is liveness, not ownership")
	}
	if r3.names[theName].PubB64 != ownerKey {
		t.Fatal("CRITICAL: restored binding has the wrong key")
	}
}

// TestFirstBootHasNoState: a missing state file is normal, not an error.
func TestFirstBootHasNoState(t *testing.T) {
	r := &registry{names: map[string]*record{}, statePath: t.TempDir() + "/absent.json"}
	n, err := r.load()
	if err != nil {
		t.Fatalf("first boot should not error: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected empty table, got %d", n)
	}
}

// TestSaveLeavesNoPartialFile: the write is atomic, so no temporary file is
// left behind and the result always parses.
func TestSaveLeavesNoPartialFile(t *testing.T) {
	dir := t.TempDir()
	state := dir + "/registry.json"
	r := &registry{names: map[string]*record{}, statePath: state}
	r.bind("a.dnx.dnxroute.com", ownerKey, addr(t, "203.0.113.7:4400"), time.Now())
	if err := r.save(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(state + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temporary file was left behind after save")
	}
	// And it round-trips.
	r2 := &registry{names: map[string]*record{}, statePath: state}
	if _, err := r2.load(); err != nil {
		t.Fatalf("saved file did not parse: %v", err)
	}
}

// TestPersistenceDisabledIsExplicit: an empty path disables persistence
// without erroring, which is what tests and ephemeral instances rely on.
func TestPersistenceDisabledIsExplicit(t *testing.T) {
	r := &registry{names: map[string]*record{}, statePath: ""}
	r.bind(theName, ownerKey, addr(t, "203.0.113.7:4400"), time.Now())
	if err := r.save(); err != nil {
		t.Fatalf("save with persistence disabled should be a no-op: %v", err)
	}
	if n, err := r.load(); err != nil || n != 0 {
		t.Fatalf("load with persistence disabled should be a no-op: n=%d err=%v", n, err)
	}
}
