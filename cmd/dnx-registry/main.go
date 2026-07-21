// dnx-registry: the DNX control plane.
//
// Runs on your VPS behind registry.dnxroute.com. Think of it as
// "living DNS": it binds FQDNs to (public key, current UDP endpoint)
// and updates in SECONDS via heartbeats — no TTL-hours staleness.
//
// It also plays matchmaker for NAT traversal: when node A wants to
// reach node B, the registry tells B "A is coming, punch back" (INTRO
// -> PUNCH), which opens both NATs simultaneously. Classic rendezvous,
// zero configuration, zero port forwarding.
//
// SECURITY MODEL (v0.1):
//   - Names bind to public keys FIRST-COME-FIRST-SERVED. A REGISTER
//     for an existing name with a different key is rejected — no hijack.
//   - Every REGISTER/RESOLVE/INTRO must be signed; timestamps must be
//     within ±30s to blunt replay.
//
// Usage:  dnx-registry --listen :4400
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"dnx/internal/proto"
)

// record is one row of the living name table.
type record struct {
	PubB64   string       // the identity key bound to this name (immutable once set)
	Endpoint *net.UDPAddr // last OBSERVED public UDP address (the NAT mapping)
	LastSeen time.Time    // heartbeat freshness
}

// registry holds the name table with concurrency protection.
type registry struct {
	mu    sync.Mutex
	names map[string]*record // FQDN -> record

	// statePath is where ownership is persisted. Empty disables persistence
	// (used by tests).
	statePath string

	// The registry's own identity. A node has no independent knowledge of a
	// peer's key — it believes what this service tells it — so an answer that
	// cannot be authenticated is an answer an on-path attacker can replace,
	// key and all.
	signPriv ed25519.PrivateKey
	signPub  string // base64
}

type registryKeyFile struct {
	PubB64  string `json:"pubkey"`
	PrivB64 string `json:"privkey"`
}

// loadOrCreateKey loads the registry's signing identity, generating one on
// first boot. An empty path yields an ephemeral key, which is what tests want.
func (r *registry) loadOrCreateKey(path string) error {
	if path == "" {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		r.signPriv, r.signPub = priv, base64.StdEncoding.EncodeToString(pub)
		return nil
	}
	if b, err := os.ReadFile(path); err == nil {
		var kf registryKeyFile
		if err := json.Unmarshal(b, &kf); err != nil {
			return fmt.Errorf("corrupt registry key %s: %w", path, err)
		}
		priv, err := base64.StdEncoding.DecodeString(kf.PrivB64)
		if err != nil || len(priv) != ed25519.PrivateKeySize {
			return fmt.Errorf("corrupt registry private key in %s", path)
		}
		r.signPriv, r.signPub = ed25519.PrivateKey(priv), kf.PubB64
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	r.signPriv = priv
	r.signPub = base64.StdEncoding.EncodeToString(pub)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(registryKeyFile{
		PubB64:  r.signPub,
		PrivB64: base64.StdEncoding.EncodeToString(priv),
	}, "", "  ")
	return os.WriteFile(path, b, 0o600)
}

// ---------------------------------------------------------------------------
// Persistence
//
// Ownership must survive a process restart for the same reason it must
// survive a node going offline: a name is owned, not leased. Without this,
// restarting the registry would un-own every name in existence and hand the
// whole namespace to whoever registered first afterwards — the same bug as
// the ten-minute prune, wearing process uptime instead of node uptime.
//
// Endpoints are deliberately NOT persisted. They are liveness, they change
// constantly, and every live node re-announces its endpoint within one
// heartbeat interval anyway.
// ---------------------------------------------------------------------------

type persistedBinding struct {
	Name     string    `json:"name"`
	PubB64   string    `json:"pubkey"`
	LastSeen time.Time `json:"last_seen"`
}

// save writes the ownership table atomically.
func (r *registry) save() error {
	if r.statePath == "" {
		return nil
	}
	r.mu.Lock()
	out := make([]persistedBinding, 0, len(r.names))
	for name, rec := range r.names {
		out = append(out, persistedBinding{Name: name, PubB64: rec.PubB64, LastSeen: rec.LastSeen})
	}
	r.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(r.statePath), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	// Write to a temporary file and rename. A crash midway through a direct
	// write would leave a truncated table, which would silently un-own every
	// name after it — exactly the failure this whole mechanism exists to
	// prevent. Rename is atomic on POSIX filesystems.
	tmp := r.statePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.statePath)
}

// load restores the ownership table. Endpoints start empty; every live node
// re-announces within one heartbeat.
func (r *registry) load() (int, error) {
	if r.statePath == "" {
		return 0, nil
	}
	b, err := os.ReadFile(r.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil // first boot
	}
	if err != nil {
		return 0, err
	}
	var in []persistedBinding
	if err := json.Unmarshal(b, &in); err != nil {
		return 0, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range in {
		r.names[p.Name] = &record{PubB64: p.PubB64, LastSeen: p.LastSeen}
	}
	return len(in), nil
}

const (
	staleAfter = 60 * time.Second // no heartbeat in 60s => ENDPOINT considered offline
	maxSkew    = 30 * time.Second // signed-timestamp tolerance (replay window)

	// bindingRetention is how long a name -> key binding survives with no
	// heartbeat at all.
	//
	// This is OWNERSHIP, and it is deliberately not the same thing as
	// liveness. An earlier version deleted the entire record after ten
	// minutes of silence, which meant that switching a machine off for
	// long enough handed its name to whoever registered next — and the
	// rightful owner was then refused its own name, because the name was
	// now bound to someone else's key. Names are owned, not leased to
	// whoever happens to be awake.
	bindingRetention = 365 * 24 * time.Hour
)

// bindResult reports what a REGISTER did, so the outcome can be tested
// without a network.
type bindResult int

const (
	bindNew       bindResult = iota // name was unclaimed; this key now owns it
	bindRefreshed                   // same key as before; endpoint updated
	bindRejected                    // name is owned by a DIFFERENT key
)

// bind applies the registration rule: the first key to claim a name owns
// it, and that ownership does not lapse merely because the node went quiet.
func (r *registry) bind(name, pubB64 string, endpoint *net.UDPAddr, now time.Time) bindResult {
	r.mu.Lock()
	rec, exists := r.names[name]
	if exists && rec.PubB64 != pubB64 {
		r.mu.Unlock()
		return bindRejected
	}
	if !exists {
		rec = &record{PubB64: pubB64}
		r.names[name] = rec
	}
	rec.Endpoint = endpoint // observed source address = live NAT mapping
	rec.LastSeen = now
	r.mu.Unlock()

	if exists {
		// A heartbeat only moved the endpoint and the timestamp, which are
		// liveness. Writing the file fifteen times a minute per node to
		// record that would be pointless; the periodic flush covers it.
		return bindRefreshed
	}

	// A brand-new claim is ownership, it is rare, and it is irreversible.
	// Persist it here rather than trusting every future caller to remember —
	// forgetting would lose the claim on the next restart, which is the
	// failure this whole mechanism exists to prevent.
	//
	// Note the lock is released first: save() takes it too.
	if err := r.save(); err != nil {
		log.Printf("WARNING: could not persist new binding for %s: %v", name, err)
	}
	return bindNew
}

// rebind transfers a name to a new key. The signature must come from the
// CURRENT key and must cover the NEW key (see proto.RebindBytes), so only the
// present owner can hand the name on, and a captured transfer cannot be
// replayed to install a different key.
//
// The endpoint is cleared: the machine that held the old key is no longer the
// owner, and the new owner must register to prove liveness.
func (r *registry) rebind(name, newPubB64, sigB64 string, ts int64, nonce string, now time.Time) error {
	if !proto.ValidPubKey(newPubB64) {
		return errors.New("new key is not a valid ed25519 public key")
	}

	r.mu.Lock()
	rec, exists := r.names[name]
	if !exists {
		r.mu.Unlock()
		return errors.New("name is not bound, so there is nothing to transfer")
	}
	current := rec.PubB64
	r.mu.Unlock()

	if current == newPubB64 {
		return errors.New("new key is the same as the current key")
	}
	if err := proto.VerifyDetached(current, proto.RebindBytes(name, newPubB64, ts, nonce), sigB64); err != nil {
		return fmt.Errorf("transfer not authorised by the current key: %w", err)
	}

	r.mu.Lock()
	rec.PubB64 = newPubB64
	rec.Endpoint = nil
	rec.LastSeen = now
	r.mu.Unlock()
	return nil
}

// release removes a binding administratively. This is the answer to a LOST
// key, which cryptography cannot solve: if the owner cannot sign, nothing
// distinguishes them from someone claiming to be them.
//
// It is deliberately NOT reachable over the network. Releasing a name is an
// authority decision, and the authority here is shell access to the machine
// running the registry.
func (r *registry) release(name string) error {
	r.mu.Lock()
	_, exists := r.names[name]
	if exists {
		delete(r.names, name)
	}
	r.mu.Unlock()
	if !exists {
		return fmt.Errorf("no binding for %q", name)
	}
	return r.save()
}

// prune separates the two lifetimes. A quiet node loses its ENDPOINT
// quickly, so nobody is told where to find something that has moved or
// gone away — but it keeps its NAME, because ownership is not liveness.
// Returns counts for logging and tests.
func (r *registry) prune(now time.Time) (wentOffline, retired int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, rec := range r.names {
		if rec.Endpoint != nil && now.Sub(rec.LastSeen) > staleAfter {
			rec.Endpoint = nil // forget WHERE it is; keep WHO owns it
			wentOffline++
			log.Printf("offline: %s (binding retained)", name)
		}
		if now.Sub(rec.LastSeen) > bindingRetention {
			delete(r.names, name)
			retired++
			log.Printf("RETIRED binding for %s after %s with no heartbeat", name, bindingRetention)
		}
	}
	return wentOffline, retired
}

func main() {
	listen := flag.String("listen", ":4400", "UDP address to listen on")
	statePath := flag.String("state", "/var/lib/dnx/registry.json",
		"file holding persisted name ownership (empty disables persistence)")
	release := flag.String("release", "",
		"administratively release a name and exit (for a lost key; requires shell access)")
	keyPath := flag.String("key", "/var/lib/dnx/registry.key",
		"the registry's own signing identity (empty generates an ephemeral one)")
	flag.Parse()

	// Releasing a name is a file operation, not a network one — do it before
	// binding anything and exit.
	//
	// NOTE FOR OPERATORS: stop the service first. A running registry holds
	// its own copy of the table in memory and will overwrite the file on its
	// next flush, silently undoing a release performed alongside it.
	if *release != "" {
		reg := &registry{names: map[string]*record{}, statePath: *statePath}
		if _, err := reg.load(); err != nil {
			log.Fatalf("cannot read ownership state from %s: %v", *statePath, err)
		}
		if err := reg.release(*release); err != nil {
			log.Fatalf("release %s: %v", *release, err)
		}
		log.Printf("released %s — the name is now unclaimed and may be registered again", *release)
		return
	}

	addr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		log.Fatalf("bad --listen: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	log.Printf("dnx-registry up on %s — the name IS the address.", *listen)

	reg := &registry{names: map[string]*record{}, statePath: *statePath}
	if err := reg.loadOrCreateKey(*keyPath); err != nil {
		log.Fatalf("registry signing identity: %v", err)
	}
	// Operators must distribute this to nodes out of band; a node that cannot
	// check the signature is trusting whoever answers.
	log.Printf("registry signing key: %s", reg.signPub)
	restored, err := reg.load()
	if err != nil {
		log.Fatalf("cannot read ownership state from %s: %v", *statePath, err)
	}
	if *statePath == "" {
		log.Printf("WARNING: persistence disabled — every name becomes unclaimed on restart")
	} else {
		log.Printf("restored %d name binding(s) from %s", restored, *statePath)
	}
	go reg.pruneLoop() // background: expire dead nodes

	buf := make([]byte, 64*1024) // max UDP datagram
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("read error: %v", err)
			continue
		}
		msg, err := proto.Decode(buf[:n])
		if err != nil {
			continue // garbage packet — ignore silently
		}
		reg.handle(conn, src, msg)
	}
}

// handle dispatches one inbound control message.
func (r *registry) handle(conn *net.UDPConn, src *net.UDPAddr, m *proto.Message) {
	switch m.Kind {

	// ---------------- REGISTER: bind/refresh a name ----------------
	case proto.KindRegister:
		if !freshTS(m.TS) {
			reply(conn, src, errMsg("stale timestamp"))
			return
		}
		// The node self-asserts its key; signature proves possession.
		if err := m.Verify(m.PubKey); err != nil {
			reply(conn, src, errMsg("bad signature"))
			return
		}
		switch r.bind(m.Name, m.PubKey, src, time.Now()) {
		case bindRejected:
			// The name is owned by a different key. This is the case that
			// protects an offline owner from having its name taken.
			log.Printf("REJECT hijack: %s from %s", m.Name, src)
			reply(conn, src, errMsg("name is bound to another key"))
			return
		case bindNew:
			log.Printf("NEW name bound: %s -> key %.12s… (at %s)", m.Name, m.PubKey, src)
		}

		// Ack echoes back the observed endpoint — lets the node learn
		// its own public address (STUN-lite, for free).
		reply(conn, src, &proto.Message{
			Kind:     proto.KindRegisterAck,
			Name:     m.Name,
			Endpoint: src.String(),
		})

	// ---------------- RESOLVE: name -> (key, endpoint) ----------------
	case proto.KindRebind:
		if !freshTS(m.TS) {
			reply(conn, src, errMsg("stale timestamp"))
			return
		}
		// m.PubKey carries the NEW key; the signature is by the CURRENT one.
		if err := r.rebind(m.Name, m.PubKey, m.Sig, m.TS, m.Nonce, time.Now()); err != nil {
			log.Printf("REBIND refused for %s: %v", m.Name, err)
			reply(conn, src, errMsg(err.Error()))
			return
		}
		log.Printf("REBIND: %s transferred to key %.12s… (endpoint cleared)", m.Name, m.PubKey)
		if err := r.save(); err != nil {
			log.Printf("WARNING: could not persist transfer of %s: %v", m.Name, err)
		}
		reply(conn, src, &proto.Message{Kind: proto.KindRebindAck, Name: m.Name})

	case proto.KindResolve:
		r.mu.Lock()
		rec, ok := r.names[m.Target]
		fresh := ok && rec.Endpoint != nil && time.Since(rec.LastSeen) < staleAfter
		var resp *proto.Message
		if fresh {
			ep := rec.Endpoint.String()
			ts := time.Now().UnixMilli()
			resp = &proto.Message{
				Kind:     proto.KindResolveResp,
				Target:   m.Target,
				PubKey:   rec.PubB64, // the caller has no other source for this
				Endpoint: ep,         // plumbing, never shown to humans
				TS:       ts,
				Nonce:    m.Nonce, // echo: binds this answer to that question
			}
			resp.Sig = proto.SignDetached(r.signPriv,
				proto.ResolveRespBytes(m.Target, rec.PubB64, ep, ts, m.Nonce))
		} else {
			resp = errMsg("unknown or offline: " + m.Target)
		}
		r.mu.Unlock()
		reply(conn, src, resp)

	// ---------------- INTRO: rendezvous for NAT punching ----------------
	case proto.KindIntro:
		r.mu.Lock()
		rec, ok := r.names[m.Target]
		fresh := ok && rec.Endpoint != nil && time.Since(rec.LastSeen) < staleAfter
		var target *net.UDPAddr
		if fresh {
			target = rec.Endpoint
		}
		r.mu.Unlock()
		if target == nil {
			reply(conn, src, errMsg("cannot introduce, target offline: "+m.Target))
			return
		}
		// Tell the TARGET who's knocking and from where. The target will
		// fire packets back at src, opening its own NAT outbound —
		// simultaneous punch, both cones open, direct P2P achieved.
		log.Printf("INTRO %s -> %s", m.Name, m.Target)
		reply(conn, target, &proto.Message{
			Kind:     proto.KindPunch,
			Name:     m.Name,       // who is knocking (FQDN — names everywhere)
			Endpoint: src.String(), // where to punch back
		})

	default:
		// Registry only speaks control plane; PING/PONG are node-to-node.
	}
}

// pruneLoop drops records that stopped heartbeating.
func (r *registry) pruneLoop() {
	for range time.Tick(30 * time.Second) {
		r.prune(time.Now())
		// Flush refreshed timestamps and any retirements.
		if err := r.save(); err != nil {
			log.Printf("WARNING: could not persist ownership table: %v", err)
		}
	}
}

// ---- tiny helpers ----

func reply(conn *net.UDPConn, to *net.UDPAddr, m *proto.Message) {
	conn.WriteToUDP(proto.Encode(m), to)
}

func errMsg(info string) *proto.Message {
	return &proto.Message{Kind: proto.KindError, Info: info}
}

// freshTS enforces the ±30s replay window on signed timestamps.
func freshTS(tsMillis int64) bool {
	t := time.UnixMilli(tsMillis)
	d := time.Since(t)
	if d < 0 {
		d = -d
	}
	return d < maxSkew
}
