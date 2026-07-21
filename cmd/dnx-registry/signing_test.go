package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"dnx/internal/proto"
)

// These tests cover the weakness that turned out to be the most serious in
// the whole system.
//
// A resolution answer carries the peer's public key, and a node has no other
// source for it — the handshake is then checked against exactly that key. So
// an attacker who can forge the answer does not merely misdirect traffic: it
// supplies a key it holds, completes a valid handshake, and the caller
// reports identity_verified=true for a machine that does not own the name.
//
// The whole identity guarantee therefore rests on this one message being
// authentic.

func registryWithKey(t *testing.T) *registry {
	t.Helper()
	r := newTestRegistry()
	if err := r.loadOrCreateKey(""); err != nil {
		t.Fatal(err)
	}
	return r
}

// signedAnswer reproduces what the registry sends for a resolution.
func signedAnswer(r *registry, target, peerKey, endpoint string, ts int64, nonce string) string {
	return proto.SignDetached(r.signPriv, proto.ResolveRespBytes(target, peerKey, endpoint, ts, nonce))
}

// TestGenuineAnswerVerifies is the baseline.
func TestGenuineAnswerVerifies(t *testing.T) {
	r := registryWithKey(t)
	ts, nonce := time.Now().UnixMilli(), "q1"
	const target, peerKey, ep = "bob.dnx.dnxroute.com", "BOBS_REAL_KEY", "203.0.113.9:4400"

	sig := signedAnswer(r, target, peerKey, ep, ts, nonce)
	if err := proto.VerifyDetached(r.signPub,
		proto.ResolveRespBytes(target, peerKey, ep, ts, nonce), sig); err != nil {
		t.Fatalf("a genuine answer should verify: %v", err)
	}
}

// TestSubstitutedKeyIsCaught is the attack itself: the attacker keeps the
// name and endpoint but swaps in a key it controls.
func TestSubstitutedKeyIsCaught(t *testing.T) {
	r := registryWithKey(t)
	ts, nonce := time.Now().UnixMilli(), "q2"
	const target, realKey, ep = "bob.dnx.dnxroute.com", "BOBS_REAL_KEY", "203.0.113.9:4400"

	genuine := signedAnswer(r, target, realKey, ep, ts, nonce)

	// Verifying the genuine signature against an answer naming a different
	// key must fail — otherwise the signature would attest to nothing useful.
	if err := proto.VerifyDetached(r.signPub,
		proto.ResolveRespBytes(target, "ATTACKERS_KEY", ep, ts, nonce), genuine); err == nil {
		t.Fatal("CRITICAL: a substituted peer key passed verification — impersonation is possible")
	}
}

// TestSubstitutedEndpointIsCaught: redirecting traffic is also refused.
func TestSubstitutedEndpointIsCaught(t *testing.T) {
	r := registryWithKey(t)
	ts, nonce := time.Now().UnixMilli(), "q3"
	const target, key = "bob.dnx.dnxroute.com", "BOBS_REAL_KEY"

	genuine := signedAnswer(r, target, key, "203.0.113.9:4400", ts, nonce)
	if err := proto.VerifyDetached(r.signPub,
		proto.ResolveRespBytes(target, key, "198.51.100.6:4400", ts, nonce), genuine); err == nil {
		t.Fatal("CRITICAL: a substituted endpoint passed verification")
	}
}

// TestAnswerForAnotherNameIsCaught: an answer about alice must not be
// accepted as an answer about bob.
func TestAnswerForAnotherNameIsCaught(t *testing.T) {
	r := registryWithKey(t)
	ts, nonce := time.Now().UnixMilli(), "q4"
	const key, ep = "SOME_KEY", "203.0.113.9:4400"

	forAlice := signedAnswer(r, "alice.dnx.dnxroute.com", key, ep, ts, nonce)
	if err := proto.VerifyDetached(r.signPub,
		proto.ResolveRespBytes("bob.dnx.dnxroute.com", key, ep, ts, nonce), forAlice); err == nil {
		t.Fatal("CRITICAL: an answer about one name verified as an answer about another")
	}
}

// TestAnotherRegistryCannotAnswer: only the registry a node was configured to
// trust may answer for it. This is what makes federation safe later — a
// forged referral is exactly this attack one level up.
func TestAnotherRegistryCannotAnswer(t *testing.T) {
	honest := registryWithKey(t)
	rogue := registryWithKey(t)
	ts, nonce := time.Now().UnixMilli(), "q5"
	const target, key, ep = "bob.dnx.dnxroute.com", "KEY", "203.0.113.9:4400"

	sig := signedAnswer(rogue, target, key, ep, ts, nonce)
	if err := proto.VerifyDetached(honest.signPub,
		proto.ResolveRespBytes(target, key, ep, ts, nonce), sig); err == nil {
		t.Fatal("CRITICAL: a different registry's signature was accepted")
	}
}

// TestRegistryKeyPersists: the key must survive a restart, or every node's
// pinned copy would break on every deploy.
func TestRegistryKeyPersists(t *testing.T) {
	path := t.TempDir() + "/registry.key"

	r1 := newTestRegistry()
	if err := r1.loadOrCreateKey(path); err != nil {
		t.Fatal(err)
	}
	first := r1.signPub

	r2 := newTestRegistry()
	if err := r2.loadOrCreateKey(path); err != nil {
		t.Fatal(err)
	}
	if r2.signPub != first {
		t.Fatal("CRITICAL: the registry's signing key changed across a restart")
	}

	// And it is a usable keypair, not just matching strings.
	msg := proto.ResolveRespBytes("x.dnx.dnxroute.com", "k", "1.2.3.4:1", 1, "n")
	if err := proto.VerifyDetached(r2.signPub, msg, proto.SignDetached(r2.signPriv, msg)); err != nil {
		t.Fatalf("restored key does not sign correctly: %v", err)
	}
}

// TestEphemeralKeyWhenUnconfigured: tests and throwaway instances need a key
// without touching disk.
func TestEphemeralKeyWhenUnconfigured(t *testing.T) {
	r := newTestRegistry()
	if err := r.loadOrCreateKey(""); err != nil {
		t.Fatal(err)
	}
	if !proto.ValidPubKey(r.signPub) {
		t.Fatal("ephemeral key should still be a valid ed25519 public key")
	}
	if len(r.signPriv) != ed25519.PrivateKeySize {
		t.Fatal("ephemeral private key is the wrong size")
	}
	_ = base64.StdEncoding
	_ = rand.Reader
}
