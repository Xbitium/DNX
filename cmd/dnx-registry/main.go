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
	"flag"
	"log"
	"net"
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
	defer r.mu.Unlock()

	rec, exists := r.names[name]
	if exists && rec.PubB64 != pubB64 {
		return bindRejected
	}
	if !exists {
		rec = &record{PubB64: pubB64}
		r.names[name] = rec
	}
	rec.Endpoint = endpoint // observed source address = live NAT mapping
	rec.LastSeen = now
	if exists {
		return bindRefreshed
	}
	return bindNew
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
	flag.Parse()

	addr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		log.Fatalf("bad --listen: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("dnx-registry up on %s — the name IS the address.", *listen)

	reg := &registry{names: map[string]*record{}}
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
	case proto.KindResolve:
		r.mu.Lock()
		rec, ok := r.names[m.Target]
		fresh := ok && rec.Endpoint != nil && time.Since(rec.LastSeen) < staleAfter
		var resp *proto.Message
		if fresh {
			resp = &proto.Message{
				Kind:     proto.KindResolveResp,
				Target:   m.Target,
				PubKey:   rec.PubB64,          // caller verifies pongs against this
				Endpoint: rec.Endpoint.String(), // plumbing, never shown to humans
			}
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
