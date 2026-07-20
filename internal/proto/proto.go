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
