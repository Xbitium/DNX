package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"dnx/internal/proto"
)

type kp struct {
	pub  string
	priv ed25519.PrivateKey
}

func newKP(t *testing.T) kp {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return kp{pub: base64.StdEncoding.EncodeToString(pub), priv: priv}
}

// signTransfer produces what the current owner would send to hand `name` to
// newPub.
func signTransfer(owner kp, name, newPub string, ts int64, nonce string) string {
	return proto.SignDetached(owner.priv, proto.RebindBytes(name, newPub, ts, nonce))
}

// TestOwnerCanTransferName: planned key rotation. The holder of the current
// key hands the name to a new key, and the new key takes over.
func TestOwnerCanTransferName(t *testing.T) {
	r := newTestRegistry()
	now := time.Now()
	owner, successor := newKP(t), newKP(t)

	r.bind(theName, owner.pub, addr(t, "203.0.113.7:4400"), now)

	ts, nonce := now.UnixMilli(), "n1"
	sig := signTransfer(owner, theName, successor.pub, ts, nonce)
	if err := r.rebind(theName, successor.pub, sig, ts, nonce, now); err != nil {
		t.Fatalf("the current owner should be able to transfer: %v", err)
	}

	// The old key is now a stranger.
	if got := r.bind(theName, owner.pub, addr(t, "203.0.113.7:4400"), now); got != bindRejected {
		t.Fatalf("CRITICAL: the previous key still owns the name (got %v)", got)
	}
	// The new key is recognised.
	if got := r.bind(theName, successor.pub, addr(t, "198.51.100.9:4400"), now); got != bindRefreshed {
		t.Fatalf("the successor key should own the name now (got %v)", got)
	}
}

// TestTransferClearsEndpoint: the machine holding the old key is no longer
// the owner, so nobody should be directed to it until the new owner
// registers and proves it is live.
func TestTransferClearsEndpoint(t *testing.T) {
	r := newTestRegistry()
	now := time.Now()
	owner, successor := newKP(t), newKP(t)
	r.bind(theName, owner.pub, addr(t, "203.0.113.7:4400"), now)

	ts, nonce := now.UnixMilli(), "n2"
	if err := r.rebind(theName, successor.pub, signTransfer(owner, theName, successor.pub, ts, nonce), ts, nonce, now); err != nil {
		t.Fatal(err)
	}
	if ep := r.names[theName].Endpoint; ep != nil {
		t.Fatalf("CRITICAL: endpoint survived a transfer, pointing at the previous owner: %v", ep)
	}
}

// TestStrangerCannotTransfer: someone who does not hold the current key
// cannot move the name, however well-formed their request.
func TestStrangerCannotTransfer(t *testing.T) {
	r := newTestRegistry()
	now := time.Now()
	owner, attacker := newKP(t), newKP(t)
	r.bind(theName, owner.pub, addr(t, "203.0.113.7:4400"), now)

	ts, nonce := now.UnixMilli(), "n3"
	// Attacker signs with their own key, trying to take the name.
	sig := signTransfer(attacker, theName, attacker.pub, ts, nonce)
	if err := r.rebind(theName, attacker.pub, sig, ts, nonce, now); err == nil {
		t.Fatal("CRITICAL: a stranger transferred a name they never owned")
	}
	if r.names[theName].PubB64 != owner.pub {
		t.Fatal("CRITICAL: the binding changed despite the transfer being refused")
	}
}

// TestCapturedTransferCannotBeRedirected is the reason REBIND has its own
// signing string.
//
// The ordinary message signature deliberately omits the key field, which is
// right for REGISTER where the key is self-asserted. Reusing it here would
// mean a transfer signature said only "move this name" without saying where.
// Anyone who observed one legitimate transfer could then replay that
// signature to install a key of their own. Binding the destination key into
// the signed bytes is what makes a captured transfer worthless.
func TestCapturedTransferCannotBeRedirected(t *testing.T) {
	r := newTestRegistry()
	now := time.Now()
	owner, intended, attacker := newKP(t), newKP(t), newKP(t)
	r.bind(theName, owner.pub, addr(t, "203.0.113.7:4400"), now)

	ts, nonce := now.UnixMilli(), "n4"
	// A genuine transfer to the intended successor, observed on the wire.
	captured := signTransfer(owner, theName, intended.pub, ts, nonce)

	// The attacker replays it, substituting their own key as the destination.
	if err := r.rebind(theName, attacker.pub, captured, ts, nonce, now); err == nil {
		t.Fatal("CRITICAL: a captured transfer was redirected to an attacker's key")
	}
	if r.names[theName].PubB64 != owner.pub {
		t.Fatal("CRITICAL: binding moved during a replayed transfer")
	}

	// The same signature still works for the destination it actually named.
	if err := r.rebind(theName, intended.pub, captured, ts, nonce, now); err != nil {
		t.Fatalf("the genuine transfer should still succeed: %v", err)
	}
}

func TestTransferRejectsGarbage(t *testing.T) {
	r := newTestRegistry()
	now := time.Now()
	owner := newKP(t)
	r.bind(theName, owner.pub, addr(t, "203.0.113.7:4400"), now)
	ts, nonce := now.UnixMilli(), "n5"

	if err := r.rebind(theName, "not-a-key", "sig", ts, nonce, now); err == nil {
		t.Fatal("a malformed destination key should be refused")
	}
	if err := r.rebind(theName, owner.pub, signTransfer(owner, theName, owner.pub, ts, nonce), ts, nonce, now); err == nil {
		t.Fatal("transferring a name to the key that already holds it should be refused")
	}
	if err := r.rebind("never.bound.dnxroute.com", newKP(t).pub, "sig", ts, nonce, now); err == nil {
		t.Fatal("transferring an unbound name should be refused")
	}
}

// TestAdministrativeRelease covers the case cryptography cannot: the key is
// gone, so nobody can sign anything, and the name must be freed by whoever
// runs the registry.
func TestAdministrativeRelease(t *testing.T) {
	dir := t.TempDir()
	r := &registry{names: map[string]*record{}, statePath: dir + "/registry.json"}
	now := time.Now()
	lost, replacement := newKP(t), newKP(t)

	r.bind(theName, lost.pub, addr(t, "203.0.113.7:4400"), now)

	// Nobody else can take it while it is bound.
	if got := r.bind(theName, replacement.pub, addr(t, "198.51.100.9:4400"), now); got != bindRejected {
		t.Fatalf("name should be protected before release (got %v)", got)
	}

	if err := r.release(theName); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := r.release(theName); err == nil {
		t.Fatal("releasing an unbound name should report that there was nothing to release")
	}

	// Now the replacement machine can claim it.
	if got := r.bind(theName, replacement.pub, addr(t, "198.51.100.9:4400"), now); got != bindNew {
		t.Fatalf("after release the name should be claimable (got %v)", got)
	}

	// And the release was persisted, not just applied in memory.
	r2 := &registry{names: map[string]*record{}, statePath: dir + "/registry.json"}
	if _, err := r2.load(); err != nil {
		t.Fatal(err)
	}
	if r2.names[theName].PubB64 != replacement.pub {
		t.Fatal("the new binding should have survived a restart")
	}
}
