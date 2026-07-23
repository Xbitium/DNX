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
	"dnx/internal/zone"
)

// sealedPayload is what travels INSIDE an encrypted frame.
// v0.1 sent this as plaintext JSON; v0.2 seals it. Same semantics,
// now confidential. (v0.3 will carry stream data here too.)
type sealedPayload struct {
	Kind  string `json:"k"`           // "PING"|"PONG"|"OPEN"|"OPENOK"|"OPENERR"
	Name  string `json:"n"`           // sender's FQDN
	Nonce string `json:"x,omitempty"` // echoed for RTT matching
	TS    int64  `json:"t,omitempty"`

	// ---- tunnel control (see tunnel.go) ----
	SID  uint32 `json:"s,omitempty"` // stream id, scoped to this session
	Port int    `json:"p,omitempty"` // target TCP port for OPEN
	Info string `json:"i,omitempty"` // error detail for OPENERR

	// Probe marks an OPEN that only asks whether a tunnel WOULD be accepted.
	// The responder checks its allowlist and confirms the local service is
	// listening, then closes immediately without creating a stream.
	Probe bool `json:"pr,omitempty"`
}

// ---------------------------------------------------------------------------
// Establishing a session (initiator side)
// ---------------------------------------------------------------------------

// getSession returns a usable encrypted session with peerName, performing a
// handshake if none exists or the existing one has expired (5-minute rekey).
// peerIDKey is the ed25519 key the REGISTRY bound to that name — this is what
// makes the session trustworthy.
func (a *agent) getSession(peerName, peerIDKey string, peerAddr *net.UDPAddr, timeout time.Duration) (*secure.Session, error) {
	a.mu.Lock()
	ps, ok := a.sessions[peerName]

	// Reuse a live, unexpired session.
	if ok && ps.sess != nil && !ps.sess.Expired() {
		s := ps.sess
		ps.addr = peerAddr // endpoint may have moved under NAT; name/key did not
		a.mu.Unlock()
		return s, nil
	}

	// A handshake is already in flight — wait for it instead of starting a second.
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

	// ---- Start a fresh handshake (we are the INITIATOR) ----
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

	// HS_INIT: our ephemeral X25519 key, SIGNED by our long-term identity key.
	ts := time.Now().UnixMilli()
	msg := &proto.Message{
		Kind:   proto.KindHSInit,
		Name:   a.id.Name,
		Target: peerName,
		PubKey: a.id.PubB64, // so the peer can verify us without a registry round-trip
		EphPub: secure.EncodeEphPub(eph.Pub),
		Nonce:  ps.nonceA,
		TS:     ts,
	}
	msg.Sig = secure.SignHandshake(a.id.Priv(),
		secure.HandshakeBytes("HS_INIT", a.id.Name, peerName, eph.Pub, ps.nonceA, "", ts))

	log.Printf("handshake -> %s (initiating encrypted session)", peerName)

	// Retry the INIT: the first packets also serve as NAT punch traffic.
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

	// Wait for handleHSResp to complete the session.
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

// ---------------------------------------------------------------------------
// Responder side: someone wants an encrypted channel with US
// ---------------------------------------------------------------------------

func (a *agent) handleHSInit(src *net.UDPAddr, m *proto.Message) {
	// 1. Replay window.
	if !secure.FreshTS(m.TS) {
		log.Printf("HS_INIT from %s rejected: stale timestamp", m.Name)
		return
	}

	// 2. Verify the initiator SIGNED this ephemeral key with the identity key
	//    it claims. (v0.2 note: we trust the pubkey carried in the message for
	//    now; the ping path independently verifies it against the REGISTRY's
	//    binding, which is what actually ties key -> name.)
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

	// 3. Mint our own ephemeral and derive the session.
	eph, err := secure.NewEphemeral()
	if err != nil {
		return
	}
	nonceB := secure.NewNonce()
	sess, err := secure.Derive(eph, ephPub, m.Name, m.PubKey, m.Nonce, nonceB, false) // responder
	if err != nil {
		log.Printf("HS_INIT from %s: key derivation failed: %v", m.Name, err)
		return
	}

	a.mu.Lock()
	a.sessions[m.Name] = &peerSession{sess: sess, eph: eph, addr: src}
	a.mu.Unlock()
	log.Printf("session ESTABLISHED with %s (responder, encrypted)", m.Name)

	// 4. HS_RESP: our ephemeral, echoing THEIR nonce (binds this response to
	//    this exact handshake), signed by our identity key.
	ts := time.Now().UnixMilli()
	resp := &proto.Message{
		Kind:   proto.KindHSResp,
		Name:   a.id.Name,
		Target: m.Name,
		PubKey: a.id.PubB64,
		EphPub: secure.EncodeEphPub(eph.Pub),
		Nonce:  m.Nonce, // echo
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
		return // unsolicited or already done
	}
	nonceA := ps.nonceA
	eph := ps.eph
	a.mu.Unlock()

	if !secure.FreshTS(m.TS) {
		return
	}
	// The echoed nonce MUST match ours, or this response belongs to another handshake.
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

	sess, err := secure.Derive(eph, ephPub, m.Name, m.PubKey, nonceA, m.NonceB, true) // initiator
	if err != nil {
		return
	}

	a.mu.Lock()
	ps.sess = sess
	ps.addr = src
	if ps.done != nil {
		close(ps.done) // unblock getSession
		ps.done = nil
	}
	a.mu.Unlock()
	log.Printf("session ESTABLISHED with %s (initiator, encrypted)", m.Name)
}

// ---------------------------------------------------------------------------
// Sealed frames: everything after the handshake
// ---------------------------------------------------------------------------

// handleSealed decrypts an inbound sealed frame and acts on its payload.
// We must find the right session by ADDRESS, since the frame header carries
// no name — that's the point: sealed frames leak nothing on the wire.
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
		return // no session for this address — can't decrypt, drop silently
	}

	pt, err := ps.sess.Open(frame) // authenticates AND decrypts
	if err != nil {
		log.Printf("sealed frame from %s rejected: %v", src, err)
		return
	}

	// Stream data is binary, prefixed 0x02; JSON control payloads start
	// with '{'. One sealed channel carries both unambiguously.
	if sid, sf, ok := decodeStreamPayload(pt); ok {
		if ts := a.tunnels.get(sid); ts != nil {
			ts.stream.OnFrame(sf)
		}
		return
	}

	var p sealedPayload
	if json.Unmarshal(pt, &p) != nil {
		return
	}

	// Lets tunnel handlers reply on this same session.
	seal := func(b []byte) []byte { return ps.sess.Seal(b) }

	switch p.Kind {
	case "PING":
		// Reply inside the SAME encrypted session. No signature needed:
		// the AEAD tag already proves the sender holds the session key,
		// which only the owner of the name could have derived.
		out, _ := json.Marshal(sealedPayload{
			Kind: "PONG", Name: a.id.Name, Nonce: p.Nonce, TS: time.Now().UnixMilli(),
		})
		a.conn.WriteToUDP(ps.sess.Seal(out), src)

	case "PONG":
		// Route to whoever is waiting on this nonce.
		a.deliver(&proto.Message{Kind: proto.KindPong, Name: p.Name, Nonce: p.Nonce})

	case "OPEN":
		go a.handleTunnelOpen(p.Name, p, seal, src)

	case "OPENOK":
		log.Printf("tunnel %d: peer %s accepted", p.SID, p.Name)
		// Wake anyone waiting on a probe.
		a.deliver(&proto.Message{Kind: proto.KindPong, Nonce: tunnelWaitKey(p.SID)})

	case "OPENERR":
		log.Printf("tunnel %d: peer %s refused: %s", p.SID, p.Name, p.Info)
		a.deliver(&proto.Message{Kind: proto.KindError, Nonce: tunnelWaitKey(p.SID), Info: p.Info})
		if ts := a.tunnels.get(p.SID); ts != nil {
			ts.close()
			a.tunnels.remove(p.SID)
		}
	}
}

// ---------------------------------------------------------------------------
// Encrypted ping — the v0.2 headline
// ---------------------------------------------------------------------------

// pingEncrypted resolves a name, establishes (or reuses) an encrypted session,
// and sends a ping INSIDE that session. Compared to v0.1's signed-but-plaintext
// ping, the payload is now confidential and the RTT excludes handshake cost on
// warm sessions.
func (a *agent) pingEncrypted(target string, timeout time.Duration) pingResult {
	res := pingResult{Target: target, Encrypted: true}

	// ---- Step 1: RESOLVE — get the peer's identity key + live endpoint ----
	// This may follow referrals; res.Registry is wherever it ended up.
	r, err := a.resolve(target, timeout)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	peerKey, peerAddr := r.PeerKey, r.PeerAddr

	// ---- Step 2: INTRO — cue the peer to punch back (NAT traversal, v0.1) ----
	// Sent to the registry that answered, which for a delegated name is not
	// the one we were configured with.
	a.intro(target, r.Registry)

	// ---- Step 3: encrypted session (handshake if needed, else reuse) ----
	hsStart := time.Now()
	sess, err := a.getSession(target, peerKey, peerAddr, timeout)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.HandshakeMs = float64(time.Since(hsStart).Microseconds()) / 1000.0

	// CRITICAL CHECK: the session's peer identity key must equal the key the
	// REGISTRY bound to this name. This is where name-trust meets session-trust.
	if sess.PeerIDKey != peerKey {
		res.Error = "session key does not match the registry's binding for this name"
		return res
	}
	res.Verified = true

	// ---- Step 4: ping inside the sealed channel ----
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

	a.conn.WriteToUDP(sess.Seal(payload), addr) // ENCRYPTED on the wire

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

// resolve asks the registry for a name's identity key and live endpoint.
// maxReferrals bounds how far a chain of delegations may be followed. Each
// referral must narrow the zone, so a legitimate chain is short; a long one
// means something is wrong and following it further only helps whoever made
// it wrong.
const maxReferrals = 8

// resolve asks for a name, following delegations until an authoritative
// answer arrives.
//
// Each referral is a transfer of trust: the registry currently believed says
// "for this branch, believe that one instead, with this key". Three things
// must hold for that to be safe, and all three are checked here rather than
// assumed:
//
//   - the referral is signed by the registry we currently trust;
//   - the delegated zone actually contains the name being asked about,
//     otherwise the referral is simply misdirection;
//   - each hop narrows. A delegation that widened would let a registry
//     handed one small branch seize the namespace above it.
//
// resolution is everything a completed resolve() learned — including which
// registry ended up answering.
//
// That last field is not bookkeeping. Following a referral moves authority to
// a child registry, and EVERY later question about that name must go to
// whoever ended up authoritative — above all the INTRO that opens the NAT,
// because only the authoritative registry holds the peer's live endpoint and
// can deliver the PUNCH cue. Returning just a key and an address made that
// impossible for a caller to get right, so all three call sites got it wrong
// in the same direction: they resolved through a delegation and then asked
// the root for rendezvous. Two public peers never noticed, because they do
// not need the punch. A peer behind NAT — the case DNX exists for — did.
type resolution struct {
	PeerKey  string       // identity key the authoritative registry bound to the name
	PeerAddr *net.UDPAddr // where that peer was last observed
	Registry *net.UDPAddr // the registry that answered; ask THIS one for rendezvous
}

func (a *agent) resolve(target string, timeout time.Duration) (*resolution, error) {
	a.mu.Lock()
	curAddr := a.regAddr
	a.mu.Unlock()

	curKey := a.registryKey
	curZone := "" // the configured registry is trusted by configuration, not by referral

	deadline := time.Now().Add(timeout)

	for hop := 0; hop < maxReferrals; hop++ {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, fmt.Errorf("resolve timeout after %d referral(s)", hop)
		}

		askedNonce := secure.NewNonce()
		ch := a.wait(askedNonce)

		rq := &proto.Message{
			Kind: proto.KindResolve, Name: a.id.Name, Target: target,
			TS: time.Now().UnixMilli(), Nonce: askedNonce,
		}
		rq.Sign(a.id.Priv())
		a.send(curAddr, rq)

		var m *proto.Message
		select {
		case m = <-ch:
			a.unwait(askedNonce)
		case <-time.After(remaining):
			a.unwait(askedNonce)
			return nil, fmt.Errorf("resolve timeout (registry unreachable?)")
		}

		switch m.Kind {
		case proto.KindError:
			return nil, fmt.Errorf("%s", m.Info)

		case proto.KindReferral:
			if m.Nonce != askedNonce {
				return nil, fmt.Errorf("referral does not match the question asked")
			}
			if curKey != "" {
				if err := proto.VerifyDetached(curKey,
					proto.ReferralBytes(target, m.Zone, m.Endpoint, m.PubKey, m.TS, m.Nonce), m.Sig); err != nil {
					return nil, fmt.Errorf("referral to %q failed verification, refusing to follow it: %w", m.Zone, err)
				}
			}
			if !zone.Contains(m.Zone, target) {
				return nil, fmt.Errorf("referral delegates %q, which does not contain %q", m.Zone, target)
			}
			if curZone != "" && !zone.IsNarrower(m.Zone, curZone) {
				return nil, fmt.Errorf("referral widens authority from %q to %q, refusing", curZone, m.Zone)
			}
			if !proto.ValidPubKey(m.PubKey) {
				return nil, fmt.Errorf("referral to %q carries an invalid signing key", m.Zone)
			}
			next, err := net.ResolveUDPAddr("udp", m.Endpoint)
			if err != nil {
				return nil, fmt.Errorf("referral to %q has an unusable endpoint", m.Zone)
			}
			curAddr, curKey, curZone = next, m.PubKey, m.Zone
			continue

		case proto.KindResolveResp:
			// The key here is the ONLY thing tying a name to an identity —
			// nothing downstream can catch a substitution, because the
			// handshake is checked against exactly this key.
			if curKey != "" {
				if m.Nonce != askedNonce {
					return nil, fmt.Errorf("registry answer does not match the question asked")
				}
				if err := proto.VerifyDetached(curKey,
					proto.ResolveRespBytes(m.Target, m.PubKey, m.Endpoint, m.TS, m.Nonce), m.Sig); err != nil {
					return nil, fmt.Errorf("registry answer failed verification, refusing to use it: %w", err)
				}
			}
			addr, err := net.ResolveUDPAddr("udp", m.Endpoint)
			if err != nil {
				return nil, fmt.Errorf("registry returned a bad endpoint")
			}
			return &resolution{PeerKey: m.PubKey, PeerAddr: addr, Registry: curAddr}, nil

		default:
			return nil, fmt.Errorf("unexpected reply %q while resolving", m.Kind)
		}
	}
	return nil, fmt.Errorf("gave up after %d referrals — delegation chain too long", maxReferrals)
}

// intro asks a registry to cue the peer to punch back.
//
// The registry is a parameter rather than a.regAddr on purpose. Rendezvous
// only works at the registry the name actually lives under: after a referral
// that is a child, and the configured root has delegated the branch away —
// it holds no endpoint for the name and cannot deliver the cue. Passing it in
// forces every caller to have resolved first, which is the only way it could
// know the right answer.
func (a *agent) intro(target string, reg *net.UDPAddr) {
	m := &proto.Message{
		Kind: proto.KindIntro, Name: a.id.Name, Target: target,
		TS: time.Now().UnixMilli(), Nonce: secure.NewNonce(),
	}
	m.Sign(a.id.Priv())
	a.send(reg, m)
}

// rekeyLoop drops expired sessions so the next ping re-handshakes.
// This is what delivers forward secrecy: ephemeral keys live 5 minutes, max.
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
