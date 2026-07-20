package secure

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

// helper: a fake DNX node identity (what the registry would have bound to a name)
type fakeNode struct {
	name string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	eph  *Ephemeral
}

func newFakeNode(t *testing.T, name string) *fakeNode {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	eph, err := NewEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	return &fakeNode{name: name, pub: pub, priv: priv, eph: eph}
}

func (n *fakeNode) pubB64() string { return base64.StdEncoding.EncodeToString(n.pub) }

// TestFullHandshake walks the exact 2-message flow two real nodes perform,
// then confirms both sides derive keys that interoperate in BOTH directions.
func TestFullHandshake(t *testing.T) {
	alice := newFakeNode(t, "computer1.internal.dnxroute.com")
	bob := newFakeNode(t, "computer2.internal.dnxroute.com")

	nonceA := NewNonce()
	ts := time.Now().UnixMilli()

	// ---- A -> B : HS_INIT, signed by Alice's long-term identity key ----
	initMsg := HandshakeBytes("HS_INIT", alice.name, bob.name, alice.eph.Pub, nonceA, "", ts)
	initSig := SignHandshake(alice.priv, initMsg)

	// Bob verifies against the key the REGISTRY bound to alice's name.
	if err := VerifyHandshake(alice.pubB64(), initMsg, initSig); err != nil {
		t.Fatalf("bob could not verify alice's HS_INIT: %v", err)
	}
	if !FreshTS(ts) {
		t.Fatal("timestamp should be fresh")
	}

	// ---- B -> A : HS_RESP, echoing nonceA (binds response to this handshake) ----
	nonceB := NewNonce()
	ts2 := time.Now().UnixMilli()
	respMsg := HandshakeBytes("HS_RESP", bob.name, alice.name, bob.eph.Pub, nonceA, nonceB, ts2)
	respSig := SignHandshake(bob.priv, respMsg)

	if err := VerifyHandshake(bob.pubB64(), respMsg, respSig); err != nil {
		t.Fatalf("alice could not verify bob's HS_RESP: %v", err)
	}

	// ---- both sides derive sessions ----
	aliceSess, err := Derive(alice.eph, bob.eph.Pub, bob.name, bob.pubB64(), nonceA, nonceB, true)
	if err != nil {
		t.Fatal(err)
	}
	bobSess, err := Derive(bob.eph, alice.eph.Pub, alice.name, alice.pubB64(), nonceA, nonceB, false)
	if err != nil {
		t.Fatal(err)
	}

	// ---- direction 1: alice -> bob ----
	msg1 := []byte("ssh will ride this someday")
	frame := aliceSess.Seal(msg1)
	if bytes.Contains(frame, msg1) {
		t.Fatal("CRITICAL: plaintext is visible in the sealed frame!")
	}
	got, err := bobSess.Open(frame)
	if err != nil {
		t.Fatalf("bob failed to open alice's frame: %v", err)
	}
	if !bytes.Equal(got, msg1) {
		t.Fatalf("plaintext mismatch: %q", got)
	}

	// ---- direction 2: bob -> alice (different key, must also work) ----
	msg2 := []byte("reply from the other direction")
	got2, err := aliceSess.Open(bobSess.Seal(msg2))
	if err != nil {
		t.Fatalf("alice failed to open bob's frame: %v", err)
	}
	if !bytes.Equal(got2, msg2) {
		t.Fatal("reverse direction plaintext mismatch")
	}
}

// TestImpersonationFails: an attacker with a DIFFERENT key cannot pass as the
// name's owner. This is the property the whole trust chain rests on.
func TestImpersonationFails(t *testing.T) {
	alice := newFakeNode(t, "computer1.internal.dnxroute.com")
	mallory := newFakeNode(t, "computer1.internal.dnxroute.com") // same NAME, wrong KEY

	nonceA := NewNonce()
	ts := time.Now().UnixMilli()
	msg := HandshakeBytes("HS_INIT", alice.name, "bob", mallory.eph.Pub, nonceA, "", ts)
	sig := SignHandshake(mallory.priv, msg) // signed with the WRONG identity key

	// Verifying against the key the registry bound to that name must FAIL.
	if err := VerifyHandshake(alice.pubB64(), msg, sig); err == nil {
		t.Fatal("CRITICAL: impersonation succeeded — wrong key passed verification")
	}
}

// TestTamperDetected: flipping a single bit anywhere must fail authentication.
func TestTamperDetected(t *testing.T) {
	a, b := pairedSessions(t)
	frame := a.Seal([]byte("integrity matters"))

	for _, pos := range []int{0, 3, 9, len(frame) - 1} {
		bad := append([]byte(nil), frame...)
		bad[pos] ^= 0x01 // flip one bit
		if _, err := b.Open(bad); err == nil {
			t.Fatalf("CRITICAL: tampered frame accepted (bit flipped at %d)", pos)
		}
	}
}

// TestReplayRejected: a captured frame replayed must be refused the 2nd time.
func TestReplayRejected(t *testing.T) {
	a, b := pairedSessions(t)
	frame := a.Seal([]byte("replay me"))

	if _, err := b.Open(frame); err != nil {
		t.Fatalf("first delivery should succeed: %v", err)
	}
	if _, err := b.Open(frame); err == nil {
		t.Fatal("CRITICAL: replayed frame was accepted")
	}
}

// TestNonceUniqueness: counters must be strictly monotonic (no nonce reuse,
// the classic AEAD catastrophe).
func TestNonceUniqueness(t *testing.T) {
	a, b := pairedSessions(t)
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		f := a.Seal([]byte("x"))
		hdr := string(f[:9])
		if seen[hdr] {
			t.Fatal("CRITICAL: nonce/counter reuse detected")
		}
		seen[hdr] = true
		if _, err := b.Open(f); err != nil {
			t.Fatalf("frame %d failed: %v", i, err)
		}
	}
}

// TestWrongSessionCannotDecrypt: a third party who ran their own handshake
// cannot read this session's traffic.
func TestWrongSessionCannotDecrypt(t *testing.T) {
	a, _ := pairedSessions(t)
	_, other := pairedSessions(t) // unrelated session
	if _, err := other.Open(a.Seal([]byte("secret"))); err == nil {
		t.Fatal("CRITICAL: foreign session decrypted our traffic")
	}
}

// TestSessionExpiry: rekey deadline is enforced.
func TestSessionExpiry(t *testing.T) {
	a, _ := pairedSessions(t)
	if a.Expired() {
		t.Fatal("fresh session should not be expired")
	}
	a.Established = time.Now().Add(-RekeyAfter - time.Second)
	if !a.Expired() {
		t.Fatal("session past RekeyAfter should be expired")
	}
}

// pairedSessions builds two sessions that completed a handshake with each other.
func pairedSessions(t *testing.T) (*Session, *Session) {
	t.Helper()
	alice := newFakeNode(t, "a.internal.dnxroute.com")
	bob := newFakeNode(t, "b.internal.dnxroute.com")
	nA, nB := NewNonce(), NewNonce()
	as, err := Derive(alice.eph, bob.eph.Pub, bob.name, bob.pubB64(), nA, nB, true)
	if err != nil {
		t.Fatal(err)
	}
	bs, err := Derive(bob.eph, alice.eph.Pub, alice.name, alice.pubB64(), nA, nB, false)
	if err != nil {
		t.Fatal(err)
	}
	return as, bs
}
