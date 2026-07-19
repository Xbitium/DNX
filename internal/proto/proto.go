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

const (
	KindRegister    = "REGISTER"
	KindRegisterAck = "REGISTER_ACK"
	KindResolve     = "RESOLVE"
	KindResolveResp = "RESOLVE_RESP"
	KindIntro       = "INTRO"
	KindPunch       = "PUNCH"
	KindPing        = "PING"
	KindPong        = "PONG"
	KindError       = "ERROR"

	KindHSInit = "HS_INIT"
	KindHSResp = "HS_RESP"
)

type Message struct {
	Kind     string `json:"kind"`
	Name     string `json:"name,omitempty"`
	Target   string `json:"target,omitempty"`
	PubKey   string `json:"pubkey,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	TS       int64  `json:"ts,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
	Sig      string `json:"sig,omitempty"`
	Info     string `json:"info,omitempty"`

	EphPub string `json:"eph,omitempty"`
	NonceB string `json:"nonce_b,omitempty"`
}

func (m *Message) SigningBytes() []byte {
	return []byte(fmt.Sprintf("dnx1|%s|%s|%s|%d|%s", m.Kind, m.Name, m.Target, m.TS, m.Nonce))
}

func (m *Message) Sign(priv ed25519.PrivateKey) {
	m.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, m.SigningBytes()))
}

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

func Encode(m *Message) []byte {
	b, _ := json.Marshal(m)
	return b
}

func Decode(b []byte) (*Message, error) {
	var m Message
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("undecodable DNX packet: %w", err)
	}
	return &m, nil
}
