// session.go — DNX v0.2 session layer, agent side.
//
// This file turns the crypto in internal/secure into a live protocol:
// establishing encrypted channels with peers, handling sealed frames,
// and rekeying every 5 minutes.
//
// THE TRUST CHAIN, end to end:
//
//	registry:  name  -->  ed25519 identity key      (v0.1)
//	handshake: ed25519 key SIGNS an ephemeral X25519 key
//	session:   X25519 -> HKDF -> ChaCha20-Poly1305 keys
//	=> ciphertext that only the rightful OWNER OF THE NAME can read.
//
// The registry is never trusted with a session key and never sees one.
// It is a phone book, not a key escrow.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	"dnx/internal/proto"
	"dnx/internal/secure"
)

type sealedPayload struct {
	Kind  string `json:"k"`
	Name  string `json:"n"`
	Nonce string `json:"x,omitempty"`
	TS    int64  `json:"t,omitempty"`
}

// getSession returns a usable encrypted session with peerName, performing a
// handshake if none exists or the existing one has expired (5-minute rekey).
func (a *agent) getSession(peerName, peerIDKey string, peerAddr *net.UDPAddr, timeout time.Duration) (*secure.Session, error) {
	a.mu.Lock()
	ps, ok := a.sessions[peerName]

	if ok && ps.sess != nil && !ps.sess.Expired() {
		s := ps.sess
		ps.addr = peerAddr
		a.mu.Unlock()
		return s, nil
	}

	if ok && ps.sess == nil && ps.done != nil {
		done := ps.done
		a.mu.Unlock()
		select {
		case <-done:
			a.mu.Lock()
			defer a.mu.Unlock()
			if ps.err != nil {
				return nil, ps.err
			}
			return ps.sess, nil
		case <-time.After(timeout):
			return nil, fmt.Errorf("handshake timeout with %s", peerName)
		}
	}

	eph, err := secure.NewEphemeral()
	if err != nil {
		a.mu.Unlock()
		return nil, err
	}
	ps = &peerSession{
		eph:       eph,
		addr:      peerAddr,
		nonceA:    secure.NewNonce(),
		done:      make(chan struct{}),
		initiator: true,
	}
	a.sessions[peerName] = ps
	done := ps.done
	a.mu.Unlock()

	ts := time.Now().UnixMilli()
	msg := &proto.Message{
		Kind:   proto.KindHSInit,
		Name:   a.id.Name,
		Target: peerName,
		PubKey: a.id.PubB64,
		EphPub: secure.EncodeEphPub(eph.Pub),
		Nonce:  ps.nonceA,
		TS:     ts,
	}
	msg.Sig = secure.SignHandshake(a.id.Priv(),
		secure.HandshakeBytes("HS_INIT", a.id.Name, peerName, eph.Pub, ps.nonceA, "", ts))

	log.Printf("handshake -> %s (initiating encrypted session)", peerName)

	go func() {
		tick := time.NewTicker(400 * time.Millisecond)
		defer tick.Stop()
		deadline := time.After(timeout)
		for {
			a.mu.Lock()
			addr := ps.addr
			live := ps.sess != nil
			a.mu.Unlock()
			if live {
				return
			}
			a.send(addr, msg)
			select {
			case <-tick.C:
			case <-done:
				return
			case <-deadline:
				a.mu.Lock()
				if ps.sess == nil && ps.err == nil {
					ps.err = fmt.Errorf("no HS_RESP from %s", peerName)
					close(ps.done)
					ps.done = nil
				}
				a.mu.Unlock()
				return
			}
		}
	}()

	select {
	case <-done:
		a.mu.Lock()
		defer a.mu.Unlock()
		if ps.err != nil {
			return nil, ps.err
		}
		return ps.sess, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("handshake timeout with %s", peerName)
	}
}

func (a *agent) handleHSInit(src *net.UDPAddr, m *proto.Message) {
	if !secure.FreshTS(m.TS) {
		log.Printf("HS_INIT from %s rejected: stale timestamp", m.Name)
		return
	}

	ephPub, err := secure.DecodeEphPub(m.EphPub)
	if err != nil {
		log.Printf("HS_INIT from %s rejected: %v", m.Name, err)
		return
	}
	sigMsg := secure.HandshakeBytes("HS_INIT", m.Name, a.id.Name, ephPub, m.Nonce, "", m.TS)
	if err := secure.VerifyHandshake(m.PubKey, sigMsg, m.Sig); err != nil {
		log.Printf("HS_INIT from %s REJECTED: %v", m.Name, err)
		return
	}

	eph, err := secure.NewEphemeral()
	if err != nil {
		return
	}
	nonceB := secure.NewNonce()
	sess, err := secure.Derive(eph, ephPub, m.Name, m.PubKey, m.Nonce, nonceB, false)
	if err != nil {
		log.Printf("HS_INIT from %s: key derivation failed: %v", m.Name, err)
		return
	}

	a.mu.Lock()
	a.sessions[m.Name] = &peerSession{sess: sess, eph: eph, addr: src}
	a.mu.Unlock()
	log.Printf("session ESTABLISHED with %s (responder, encrypted)", m.Name)

	ts := time.Now().UnixMilli()
	resp := &proto.Message{
		Kind:   proto.KindHSResp,
		Name:   a.id.Name,
		Target: m.Name,
		PubKey: a.id.PubB64,
		EphPub: secure.EncodeEphPub(eph.Pub),
		Nonce:  m.Nonce,
		NonceB: nonceB,
		TS:     ts,
	}
	resp.Sig = secure.SignHandshake(a.id.Priv(),
		secure.HandshakeBytes("HS_RESP", a.id.Name, m.Name, eph.Pub, m.Nonce, nonceB, ts))
	a.send(src, resp)
}

// handleHSResp completes the handshake on the INITIATOR side.
func (a *agent) handleHSResp(src *net.UDPAddr, m *proto.Message) {
	a.mu.Lock()
	ps, ok := a.sessions[m.Name]
	if !ok || !ps.initiator || ps.sess != nil {
		a.mu.Unlock()
		return
	}
	nonceA := ps.nonceA
	eph := ps.eph
	a.mu.Unlock()

	if !secure.FreshTS(m.TS) {
		return
	}
	if m.Nonce != nonceA {
		log.Printf("HS_RESP from %s rejected: nonce mismatch (replay?)", m.Name)
		return
	}
	ephPub, err := secure.DecodeEphPub(m.EphPub)
	if err != nil {
		return
	}
	sigMsg := secure.HandshakeBytes("HS_RESP", m.Name, a.id.Name, ephPub, nonceA, m.NonceB, m.TS)
	if err := secure.VerifyHandshake(m.PubKey, sigMsg, m.Sig); err != nil {
		log.Printf("HS_RESP from %s REJECTED: %v", m.Name, err)
		return
	}

	sess, err := secure.Derive(eph, ephPub, m.Name, m.PubKey, nonceA, m.NonceB, true)
	if err != nil {
		return
	}

	a.mu.Lock()
	ps.sess = sess
	ps.addr = src
	if ps.done != nil {
		close(ps.done)
		ps.done = nil
	}
	a.mu.Unlock()
	log.Printf("session ESTABLISHED with %s (initiator, encrypted)", m.Name)
}

// handleSealed decrypts an inbound sealed frame and acts on its payload.
// We find the right session by ADDRESS since the frame header carries no
// name — that's the point: sealed frames leak nothing on the wire.
func (a *agent) handleSealed(src *net.UDPAddr, frame []byte) {
	a.mu.Lock()
	var ps *peerSession
	for _, p := range a.sessions {
		if p.sess != nil && p.addr != nil && p.addr.String() == src.String() {
			ps = p
			break
		}
	}
	a.mu.Unlock()
	if ps == nil {
		return
	}

	pt, err := ps.sess.Open(frame)
	if err != nil {
		log.Printf("sealed frame from %s rejected: %v", src, err)
		return
	}

	var p sealedPayload
	if json.Unmarshal(pt, &p) != nil {
		return
	}

	switch p.Kind {
	case "PING":
		out, _ := json.Marshal(sealedPayload{
			Kind: "PONG", Name: a.id.Name, Nonce: p.Nonce, TS: time.Now().UnixMilli(),
		})
		a.conn.WriteToUDP(ps.sess.Seal(out), src)

	case "PONG":
		a.deliver(&proto.Message{Kind: proto.KindPong, Name: p.Name, Nonce: p.Nonce})
	}
}

// pingEncrypted resolves a name, establishes (or reuses) an encrypted session,
// and sends a ping INSIDE that session.
func (a *agent) pingEncrypted(target string, timeout time.Duration) pingResult {
	res := pingResult{Target: target, Encrypted: true}

	peerKey, peerAddr, err := a.resolve(target, timeout)
	if err != nil {
		res.Error = err.Error()
		return res
	}

	a.intro(target)

	hsStart := time.Now()
	sess, err := a.getSession(target, peerKey, peerAddr, timeout)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.HandshakeMs = float64(time.Since(hsStart).Microseconds()) / 1000.0

	if sess.PeerIDKey != peerKey {
		res.Error = "session key does not match the registry's binding for this name"
		return res
	}
	res.Verified = true

	nonce := secure.NewNonce()
	ch := a.wait(nonce)
	defer a.unwait(nonce)

	payload, _ := json.Marshal(sealedPayload{
		Kind: "PING", Name: a.id.Name, Nonce: nonce, TS: time.Now().UnixMilli(),
	})

	a.mu.Lock()
	addr := a.sessions[target].addr
	a.mu.Unlock()

	start := time.Now()
	deadline := time.After(timeout)
	tick := time.NewTicker(400 * time.Millisecond)
	defer tick.Stop()

	a.conn.WriteToUDP(sess.Seal(payload), addr)

	for {
		select {
		case <-ch:
			res.RTTms = float64(time.Since(start).Microseconds()) / 1000.0
			return res
		case <-tick.C:
			a.conn.WriteToUDP(sess.Seal(payload), addr)
		case <-deadline:
			res.Error = "encrypted ping timeout"
			return res
		}
	}
}

func (a *agent) resolve(target string, timeout time.Duration) (string, *net.UDPAddr, error) {
	rkey := proto.KindResolveResp + "|" + target
	ch := a.wait(rkey)
	defer a.unwait(rkey)

	a.mu.Lock()
	reg := a.regAddr
	a.mu.Unlock()

	rq := &proto.Message{
		Kind: proto.KindResolve, Name: a.id.Name, Target: target,
		TS: time.Now().UnixMilli(), Nonce: secure.NewNonce(),
	}
	rq.Sign(a.id.Priv())
	a.send(reg, rq)

	select {
	case m := <-ch:
		if m.Kind == proto.KindError {
			return "", nil, fmt.Errorf("%s", m.Info)
		}
		addr, err := net.ResolveUDPAddr("udp", m.Endpoint)
		if err != nil {
			return "", nil, fmt.Errorf("registry returned a bad endpoint")
		}
		return m.PubKey, addr, nil
	case <-time.After(timeout):
		return "", nil, fmt.Errorf("resolve timeout (registry unreachable?)")
	}
}

func (a *agent) intro(target string) {
	a.mu.Lock()
	reg := a.regAddr
	a.mu.Unlock()
	m := &proto.Message{
		Kind: proto.KindIntro, Name: a.id.Name, Target: target,
		TS: time.Now().UnixMilli(), Nonce: secure.NewNonce(),
	}
	m.Sign(a.id.Priv())
	a.send(reg, m)
}

// rekeyLoop drops expired sessions so the next ping re-handshakes.
// This delivers forward secrecy: ephemeral keys live 5 minutes, max.
func (a *agent) rekeyLoop() {
	for range time.Tick(30 * time.Second) {
		a.mu.Lock()
		for name, ps := range a.sessions {
			if ps.sess != nil && ps.sess.Expired() {
				delete(a.sessions, name)
				log.Printf("session with %s expired (5-min rekey) — will re-handshake on next use", name)
			}
		}
		a.mu.Unlock()
	}
}
