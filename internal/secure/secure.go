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

const (
	RekeyAfter       = 5 * time.Minute
	HandshakeTimeout = 8 * time.Second
	MaxSkew          = 30 * time.Second

	dirInitiator = "dnx v0.2 initiator->responder"
	dirResponder = "dnx v0.2 responder->initiator"
)

type Ephemeral struct {
	priv [32]byte
	Pub  [32]byte
}

func NewEphemeral() (*Ephemeral, error) {
	e := &Ephemeral{}
	if _, err := io.ReadFull(rand.Reader, e.priv[:]); err != nil {
		return nil, err
	}
	pub, err := curve25519.X25519(e.priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(e.Pub[:], pub)
	return e, nil
}

func (e *Ephemeral) shared(peerPub [32]byte) ([]byte, error) {
	s, err := curve25519.X25519(e.priv[:], peerPub[:])
	if err != nil {
		return nil, fmt.Errorf("X25519 failed (invalid peer key?): %w", err)
	}
	return s, nil
}

// HandshakeBytes builds the canonical string signed during a handshake.
// This is the hinge of the whole design: the long-term identity key (which
// the REGISTRY has bound to a NAME) signs over the ephemeral key. A peer
// that verifies this signature against the resolved identity key knows the
// session key belongs to the rightful owner of the name.
func HandshakeBytes(tag, selfName, peerName string, eph [32]byte, nonceA, nonceB string, ts int64) []byte {
	return []byte(fmt.Sprintf("dnx2|%s|%s|%s|%s|%s|%s|%d",
		tag, selfName, peerName,
		base64.StdEncoding.EncodeToString(eph[:]),
		nonceA, nonceB, ts))
}

func SignHandshake(priv ed25519.PrivateKey, msg []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
}

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

func FreshTS(tsMillis int64) bool {
	d := time.Since(time.UnixMilli(tsMillis))
	if d < 0 {
		d = -d
	}
	return d < MaxSkew
}

func deriveKey(shared []byte, nonceA, nonceB, info string) ([]byte, error) {
	salt := []byte(nonceA + nonceB)
	r := hkdf.New(sha256.New, shared, salt, []byte(info))
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// Session holds the directional AEAD ciphers for one peer. Safe for concurrent use.
type Session struct {
	PeerName    string
	PeerIDKey   string
	Established time.Time

	sendAEAD cipher.AEAD
	recvAEAD cipher.AEAD

	mu      sync.Mutex
	counter uint64
	seen    map[uint64]struct{}
}

func NewSession(peerName, peerIDKey string, shared []byte, nonceA, nonceB string, initiator bool) (*Session, error) {
	kInit, err := deriveKey(shared, nonceA, nonceB, dirInitiator)
	if err != nil {
		return nil, err
	}
	kResp, err := deriveKey(shared, nonceA, nonceB, dirResponder)
	if err != nil {
		return nil, err
	}

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

func (s *Session) Expired() bool {
	return time.Since(s.Established) > RekeyAfter
}

const (
	FrameMagic = 0xD8
	headerLen  = 1 + 8
	nonceLen   = chacha20poly1305.NonceSize
)

func (s *Session) Seal(plaintext []byte) []byte {
	s.mu.Lock()
	ctr := s.counter
	s.counter++
	s.mu.Unlock()

	hdr := make([]byte, headerLen)
	hdr[0] = FrameMagic
	binary.BigEndian.PutUint64(hdr[1:], ctr)

	var nonce [nonceLen]byte
	binary.BigEndian.PutUint64(nonce[4:], ctr)

	ct := s.sendAEAD.Seal(nil, nonce[:], plaintext, hdr)
	return append(hdr, ct...)
}

func (s *Session) Open(frame []byte) ([]byte, error) {
	if len(frame) < headerLen+chacha20poly1305.Overhead {
		return nil, errors.New("frame too short")
	}
	if frame[0] != FrameMagic {
		return nil, errors.New("not a sealed DNX frame")
	}
	hdr := frame[:headerLen]
	ctr := binary.BigEndian.Uint64(frame[1:headerLen])

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
		return nil, fmt.Errorf("frame authentication failed: %w", err)
	}

	s.mu.Lock()
	s.seen[ctr] = struct{}{}
	s.mu.Unlock()

	return pt, nil
}

func IsSealed(b []byte) bool {
	return len(b) > 0 && b[0] == FrameMagic
}

func NewNonce() string {
	b := make([]byte, 12)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func Derive(eph *Ephemeral, peerEphPub [32]byte, peerName, peerIDKey, nonceA, nonceB string, initiator bool) (*Session, error) {
	shared, err := eph.shared(peerEphPub)
	if err != nil {
		return nil, err
	}
	return NewSession(peerName, peerIDKey, shared, nonceA, nonceB, initiator)
}

func DecodeEphPub(b64 string) ([32]byte, error) {
	var out [32]byte
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(b) != 32 {
		return out, errors.New("bad ephemeral public key")
	}
	copy(out[:], b)
	return out, nil
}

func EncodeEphPub(pub [32]byte) string {
	return base64.StdEncoding.EncodeToString(pub[:])
}
