// Package proto defines the DNX v0.1 wire protocol.
//
// DNX CORE IDEA: names are the addresses. Every message on the wire
// carries FQDNs (e.g. "computer1.internal.dnxroute.com"), never raw IPs
// at the application layer. IPs only exist transiently as "endpoints"
// inside the control plane so packets can physically move — the user
// never sees or types one.
//
// Transport for v0.1: JSON over UDP. Simple, debuggable with tcpdump,
// and UDP is required anyway for NAT hole punching. v0.2 swaps JSON
// for a compact binary framing + Noise-encrypted channels.
package proto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// ---------------------------------------------------------------------------
// Message kinds (the "verbs" of the DNX control plane)
// ---------------------------------------------------------------------------
const (
	KindRegister    = "REGISTER"     // node -> registry : "I am <name>, here's my key, bind me"
	KindRegisterAck = "REGISTER_ACK" // registry -> node : "bound, I see you at <endpoint>"
	KindResolve     = "RESOLVE"      // node -> registry : "where is <target>?"
	KindResolveResp = "RESOLVE_RESP" // registry -> node : "<target> = key K, endpoint E"
	KindIntro       = "INTRO"        // node -> registry : "introduce me to <target>" (hole punch)
	KindPunch       = "PUNCH"        // registry -> target : "<name> wants in, punch back at <endpoint>"
	KindPing        = "PING"         // node -> node : signed liveness probe (by NAME, not IP)
	KindPong        = "PONG"         // node -> node : signed reply
	KindError       = "ERROR"        // registry -> node : something went wrong (see Info)

	// ---- v0.2: session establishment (see internal/secure) ----
	// These are the ONLY node-to-node messages that stay plaintext JSON:
	// they are what BUILD the encrypted channel. Everything after them
	// rides as sealed binary frames. Both are ed25519-signed, so the
	// session key inherits the registry's name->key trust.
	KindHSInit = "HS_INIT" // node -> node : "here's my ephemeral X25519 key, signed"
	KindHSResp = "HS_RESP" // node -> node : "here's mine, echoing your nonce, signed"

	// KindRebind transfers a name to a new key. It must be signed by the
	// CURRENT key: only the present owner may hand a name on. This is the
	// only supported way to change a binding over the network — recovering a
	// name whose key is LOST is not a cryptographic problem and is handled
	// out of band by the namespace operator.
	KindRebind    = "REBIND"
	KindRebindAck = "REBIND_ACK"

	// KindReferral delegates part of the namespace to another registry.
	// A referral is a transfer of trust, so it is signed by the registry
	// making it and may only ever narrow the zone it applies to.
	KindReferral = "REFERRAL"
)

// Message is the single envelope used for ALL DNX v0.1 traffic.
// Optional fields stay empty depending on Kind — one struct keeps
// the prototype dead simple to parse and log.
type Message struct {
	Kind     string `json:"kind"`               // one of the Kind* constants above
	Name     string `json:"name,omitempty"`     // sender's FQDN identity
	Target   string `json:"target,omitempty"`   // FQDN we're asking about (RESOLVE / INTRO / PUNCH)
	PubKey   string `json:"pubkey,omitempty"`   // base64 ed25519 public key (the REAL identity)
	Endpoint string `json:"endpoint,omitempty"` // "ip:port" — control-plane plumbing only, never user-facing
	TS       int64  `json:"ts,omitempty"`       // unix-millis timestamp (replay resistance)
	Nonce    string `json:"nonce,omitempty"`    // random per-message nonce (replay resistance + RTT matching)
	Sig      string `json:"sig,omitempty"`      // base64 ed25519 signature over SigningBytes()
	Info     string `json:"info,omitempty"`     // free-text detail (errors, debug)

	// ---- v0.2 handshake fields ----
	EphPub string `json:"eph,omitempty"`     // base64 X25519 ephemeral public key
	NonceB string `json:"nonce_b,omitempty"` // responder's nonce (HS_RESP only; Nonce carries the initiator's)

	// ---- federation ----
	Zone string `json:"zone,omitempty"` // the delegated zone, on a REFERRAL
}

// SigningBytes returns the canonical byte string that gets signed.
// We sign the semantic fields only (NOT Endpoint — the registry fills
// that in from the observed UDP source address, so it can't be part
// of the node's signature).
func (m *Message) SigningBytes() []byte {
	return []byte(fmt.Sprintf("dnx1|%s|%s|%s|%d|%s", m.Kind, m.Name, m.Target, m.TS, m.Nonce))
}

// Sign fills in m.Sig using the node's private key.
func (m *Message) Sign(priv ed25519.PrivateKey) {
	m.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, m.SigningBytes()))
}

// Verify checks m.Sig against a base64-encoded public key.
// Returns nil if the signature is valid.
func (m *Message) Verify(pubB64 string) error {
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("bad public key")
	}
	sig, err := base64.StdEncoding.DecodeString(m.Sig)
	if err != nil {
		return fmt.Errorf("bad signature encoding")
	}
	if !ed25519.Verify(pub, m.SigningBytes(), sig) {
		return fmt.Errorf("signature verification FAILED for %q", m.Name)
	}
	return nil
}

// RebindBytes is the canonical string signed when transferring a name.
//
// It MUST include the new key. SigningBytes deliberately omits PubKey — that
// is correct for REGISTER, where the key is self-asserted and the signature
// proves possession of it. For a transfer it would be catastrophic: a
// signature covering only the name would authorise moving that name to *any*
// key, so anyone who observed one valid transfer could replay it to install
// a key of their own choosing. Binding the destination key into the signed
// string is what makes a captured transfer useless to an attacker.
func RebindBytes(name, newPubB64 string, ts int64, nonce string) []byte {
	return []byte(fmt.Sprintf("dnx-rebind1|%s|%s|%d|%s", name, newPubB64, ts, nonce))
}

// ResolveRespBytes is the canonical string a registry signs when answering a
// resolution.
//
// It MUST cover the public key and the endpoint. Those are precisely the
// fields an attacker would forge, and a node has no independent knowledge of
// the peer's key — it believes whatever the registry says. A signature that
// omitted them would attest only that "some answer about this name was given"
// while leaving an attacker free to substitute the key, which would make the
// signature worse than useless: it would look like assurance.
//
// The nonce echoes the request, binding the answer to the question asked.
func ResolveRespBytes(target, pubB64, endpoint string, ts int64, nonce string) []byte {
	return []byte(fmt.Sprintf("dnx-resolveresp1|%s|%s|%s|%d|%s", target, pubB64, endpoint, ts, nonce))
}

// ReferralBytes is the canonical string a registry signs when delegating.
//
// It covers the child registry's ADDRESS and its SIGNING KEY, because those
// are what the resolver will trust next. A referral that named only a zone
// would let anyone who captured it point the resolver at a registry of their
// choosing — the same substitution attack as a forged resolution answer, one
// level further up, and worse: it hands over a whole branch of the namespace
// rather than a single name.
func ReferralBytes(target, zoneName, endpoint, childKeyB64 string, ts int64, nonce string) []byte {
	return []byte(fmt.Sprintf("dnx-referral1|%s|%s|%s|%s|%d|%s",
		target, zoneName, endpoint, childKeyB64, ts, nonce))
}

// VerifyDetached checks a base64 signature over arbitrary bytes against a
// base64 ed25519 public key.
func VerifyDetached(pubB64 string, msg []byte, sigB64 string) error {
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("bad public key")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("bad signature encoding")
	}
	if !ed25519.Verify(pub, msg, sig) {
		return fmt.Errorf("signature does not verify")
	}
	return nil
}

// ValidPubKey reports whether s is a well-formed base64 ed25519 public key.
func ValidPubKey(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == ed25519.PublicKeySize
}

// SignDetached signs arbitrary bytes with an ed25519 private key.
func SignDetached(priv ed25519.PrivateKey, msg []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
}

// Encode marshals a message for the wire.
func Encode(m *Message) []byte {
	b, _ := json.Marshal(m) // struct is always marshalable; error impossible here
	return b
}

// Decode parses a raw UDP payload into a Message.
func Decode(b []byte) (*Message, error) {
	var m Message
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("undecodable DNX packet: %w", err)
	}
	return &m, nil
}
