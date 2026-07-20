// Package secure implements the DNX v0.2 session layer:
// an authenticated X25519 handshake and a ChaCha20-Poly1305 sealed channel.
//
// ------------------------------------------------------------------
// DESIGN RULE (non-negotiable): we build the PROTOCOL, never the MATH.
// All primitives come from Go's audited x/crypto. The novel work here is
// the handshake state machine and how it inherits DNX's name->key trust.
// ------------------------------------------------------------------
//
// TRUST CHAIN — the whole point:
//
//	registry binds  name --> ed25519 identity key      (v0.1, already proven)
//	handshake: ed25519 key SIGNS an ephemeral X25519 key
//	=> the session key is provably owned by the machine that owns the NAME.
//
// Encryption therefore inherits name-identity for free. Nothing new to trust.
//
// FORWARD SECRECY: the X25519 keys are ephemeral and discarded on rekey
// (every 5 minutes). Stealing a machine's long-term ed25519 key tomorrow
// does not decrypt traffic captured today.
//
// HANDSHAKE (2 messages, ~1 RTT):
//
//	A --> B  HS_INIT  { ephA_pub, nonce_A, ts, sig_A }      signed by A's ed25519
//	A <-- B  HS_RESP  { ephB_pub, nonce_A, nonce_B, sig_B } signed by B's ed25519
//	both: shared = X25519(eph_priv, peer_eph_pub)
//	      keys   = HKDF-SHA256(shared, salt=nonce_A||nonce_B, info="dnx v0.2 ...")
//
// Echoing nonce_A in HS_RESP binds the response to this exact handshake
// (anti-replay), and each side derives DIRECTIONAL keys so the two flows
// never share a nonce space.
package secure

import (
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"crypto/sha256"
)

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------
const (
	// RekeyAfter: sessions are torn down and re-handshaked on this interval.
	// 5 minutes keeps the forward-secrecy window tight (WireGuard-class).
	RekeyAfter = 5 * time.Minute

	// HandshakeTimeout: how long we wait for HS_RESP before giving up.
	HandshakeTimeout = 8 * time.Second

	// MaxSkew: handshake timestamp tolerance (replay window).
	MaxSkew = 30 * time.Second

	// Direction labels — each side encrypts with a DIFFERENT key, so the
	// two directions can never collide in nonce space.
	dirInitiator = "dnx v0.2 initiator->responder"
	dirResponder = "dnx v0.2 responder->initiator"
)

// ---------------------------------------------------------------------------
// Ephemeral keypair (X25519)
// ---------------------------------------------------------------------------

// Ephemeral is a single-session X25519 keypair. Discarded on rekey.
type Ephemeral struct {
	priv [32]byte
	Pub  [32]byte
}

// NewEphemeral mints a fresh X25519 keypair from the OS CSPRNG.
func NewEphemeral() (*Ephemeral, error) {
	e := &Ephemeral{}
	if _, err := io.ReadFull(rand.Reader, e.priv[:]); err != nil {
		return nil, err
	}
	// Derive the public key: pub = priv * basepoint.
	pub, err := curve25519.X25519(e.priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(e.Pub[:], pub)
	return e, nil
}

// shared computes the X25519 shared secret with a peer's ephemeral public key.
func (e *Ephemeral) shared(peerPub [32]byte) ([]byte, error) {
	s, err := curve25519.X25519(e.priv[:], peerPub[:])
	if err != nil {
		return nil, fmt.Errorf("X25519 failed (invalid peer key?): %w", err)
	}
	return s, nil
}

// ---------------------------------------------------------------------------
// Handshake binding: what the ed25519 identity actually signs
// ---------------------------------------------------------------------------

// HandshakeBytes builds the canonical string signed during a handshake.
// This is the hinge of the whole design: the long-term identity key (which
// the REGISTRY has bound to a NAME) signs over the ephemeral key. A peer
// that verifies this signature against the resolved identity key knows the
// session key belongs to the rightful owner of the name.
//
// tag: "HS_INIT" or "HS_RESP" — domain separation, so an INIT signature can
// never be replayed as a RESP signature.
func HandshakeBytes(tag, selfName, peerName string, eph [32]byte, nonceA, nonceB string, ts int64) []byte {
	return []byte(fmt.Sprintf("dnx2|%s|%s|%s|%s|%s|%s|%d",
		tag, selfName, peerName,
		base64.StdEncoding.EncodeToString(eph[:]),
		nonceA, nonceB, ts))
}

// SignHandshake signs the canonical handshake string with the node's
// long-term ed25519 identity key.
func SignHandshake(priv ed25519.PrivateKey, msg []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
}

// VerifyHandshake checks a handshake signature against a peer's ed25519
// public key — the very key the registry bound to the peer's NAME.
func VerifyHandshake(peerPubB64 string, msg []byte, sigB64 string) error {
	pub, err := base64.StdEncoding.DecodeString(peerPubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("bad peer identity key")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return errors.New("bad signature encoding")
	}
	if !ed25519.Verify(pub, msg, sig) {
		return errors.New("handshake signature invalid — peer does not own this name's key")
	}
	return nil
}

// FreshTS enforces the handshake replay window.
func FreshTS(tsMillis int64) bool {
	d := time.Since(time.UnixMilli(tsMillis))
	if d < 0 {
		d = -d
	}
	return d < MaxSkew
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

// deriveKey runs HKDF-SHA256 over the X25519 shared secret.
// salt = nonceA||nonceB ties the keys to THIS handshake; info separates
// the two directions so each flow gets its own key.
func deriveKey(shared []byte, nonceA, nonceB, info string) ([]byte, error) {
	salt := []byte(nonceA + nonceB)
	r := hkdf.New(sha256.New, shared, salt, []byte(info))
	key := make([]byte, chacha20poly1305.KeySize) // 32 bytes
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// ---------------------------------------------------------------------------
// Session — a live sealed channel between two named nodes
// ---------------------------------------------------------------------------

// Session holds the directional AEAD ciphers for one peer.
// Safe for concurrent use.
type Session struct {
	PeerName   string    // the FQDN on the other end (verified, not claimed)
	PeerIDKey  string    // peer's long-term ed25519 key, base64 (from the registry)
	Established time.Time // when the handshake completed

	sendAEAD cipher.AEAD // encrypt outbound with this
	recvAEAD cipher.AEAD // decrypt inbound with this

	mu      sync.Mutex
	counter uint64 // monotonic send counter — becomes the AEAD nonce
	seen    map[uint64]struct{} // replay guard: counters already accepted
}

// NewSession derives the directional keys and builds the AEAD ciphers.
// `initiator` picks which derived key is used for sending vs receiving —
// the two sides MUST disagree here, which is exactly what makes the two
// directions independent.
func NewSession(peerName, peerIDKey string, shared []byte, nonceA, nonceB string, initiator bool) (*Session, error) {
	kInit, err := deriveKey(shared, nonceA, nonceB, dirInitiator)
	if err != nil {
		return nil, err
	}
	kResp, err := deriveKey(shared, nonceA, nonceB, dirResponder)
	if err != nil {
		return nil, err
	}

	// Initiator sends with kInit and receives with kResp; responder mirrors.
	sendKey, recvKey := kInit, kResp
	if !initiator {
		sendKey, recvKey = kResp, kInit
	}

	sendAEAD, err := chacha20poly1305.New(sendKey)
	if err != nil {
		return nil, err
	}
	recvAEAD, err := chacha20poly1305.New(recvKey)
	if err != nil {
		return nil, err
	}

	return &Session{
		PeerName:    peerName,
		PeerIDKey:   peerIDKey,
		Established: time.Now(),
		sendAEAD:    sendAEAD,
		recvAEAD:    recvAEAD,
		seen:        make(map[uint64]struct{}, 1024),
	}, nil
}

// Expired reports whether this session is past its rekey deadline.
func (s *Session) Expired() bool {
	return time.Since(s.Established) > RekeyAfter
}

// ---------------------------------------------------------------------------
// Sealed frame format (binary — tight where it counts)
//
//	 0        1                9                          9+N
//	+--------+----------------+--------------------------+
//	| type   | counter (u64)  | ciphertext + 16B AEAD tag|
//	+--------+----------------+--------------------------+
//
// The counter doubles as the AEAD nonce (12B: 4 zero bytes || 8B counter),
// so nonces can never repeat within a session — and since each direction
// has its OWN key, the two sides can both count from zero safely.
// The type byte + counter are authenticated as AEAD "additional data",
// so an attacker cannot flip them without the tag failing.
// ---------------------------------------------------------------------------

const (
	FrameMagic  = 0xD8 // first byte: marks a sealed DNX v0.2 frame (vs v0.1 JSON, which starts with '{')
	headerLen   = 1 + 8
	nonceLen    = chacha20poly1305.NonceSize // 12
)

// Seal encrypts a plaintext payload into a wire frame.
func (s *Session) Seal(plaintext []byte) []byte {
	s.mu.Lock()
	ctr := s.counter
	s.counter++
	s.mu.Unlock()

	hdr := make([]byte, headerLen)
	hdr[0] = FrameMagic
	binary.BigEndian.PutUint64(hdr[1:], ctr)

	// nonce = 4 zero bytes || 8-byte counter (big endian)
	var nonce [nonceLen]byte
	binary.BigEndian.PutUint64(nonce[4:], ctr)

	// header is authenticated (additional data) but not encrypted
	ct := s.sendAEAD.Seal(nil, nonce[:], plaintext, hdr)
	return append(hdr, ct...)
}

// Open authenticates and decrypts a wire frame.
// Returns an error on: bad magic, short frame, replayed counter, or a
// failed authentication tag (i.e. tampering or wrong key).
func (s *Session) Open(frame []byte) ([]byte, error) {
	if len(frame) < headerLen+chacha20poly1305.Overhead {
		return nil, errors.New("frame too short")
	}
	if frame[0] != FrameMagic {
		return nil, errors.New("not a sealed DNX frame")
	}
	hdr := frame[:headerLen]
	ctr := binary.BigEndian.Uint64(frame[1:headerLen])

	// --- replay guard: a counter is accepted at most once per session ---
	s.mu.Lock()
	if _, dup := s.seen[ctr]; dup {
		s.mu.Unlock()
		return nil, errors.New("replayed frame counter")
	}
	s.mu.Unlock()

	var nonce [nonceLen]byte
	binary.BigEndian.PutUint64(nonce[4:], ctr)

	pt, err := s.recvAEAD.Open(nil, nonce[:], frame[headerLen:], hdr)
	if err != nil {
		// Authentication failure: tampered, forged, or wrong session key.
		return nil, fmt.Errorf("frame authentication failed: %w", err)
	}

	// Only record the counter AFTER the tag verifies, so forged frames
	// can't poison the replay table.
	s.mu.Lock()
	s.seen[ctr] = struct{}{}
	s.mu.Unlock()

	return pt, nil
}

// IsSealed reports whether a raw datagram is a v0.2 sealed frame.
// v0.1 JSON control messages start with '{', so the two coexist on one socket.
func IsSealed(b []byte) bool {
	return len(b) > 0 && b[0] == FrameMagic
}

// NewNonce mints a 96-bit random handshake nonce (base64url).
func NewNonce() string {
	b := make([]byte, 12)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Derive is the shared-secret + session constructor used by both sides.
// Kept as one function so initiator and responder cannot drift apart.
func Derive(eph *Ephemeral, peerEphPub [32]byte, peerName, peerIDKey, nonceA, nonceB string, initiator bool) (*Session, error) {
	shared, err := eph.shared(peerEphPub)
	if err != nil {
		return nil, err
	}
	return NewSession(peerName, peerIDKey, shared, nonceA, nonceB, initiator)
}

// DecodeEphPub parses a base64 X25519 public key from the wire.
func DecodeEphPub(b64 string) ([32]byte, error) {
	var out [32]byte
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(b) != 32 {
		return out, errors.New("bad ephemeral public key")
	}
	copy(out[:], b)
	return out, nil
}

// EncodeEphPub renders an X25519 public key for the wire.
func EncodeEphPub(pub [32]byte) string {
	return base64.StdEncoding.EncodeToString(pub[:])
}
