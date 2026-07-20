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
	staleAfter = 60 * time.Second // no heartbeat in 60s => node considered offline
	maxSkew    = 30 * time.Second // signed-timestamp tolerance (replay window)
)

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
		r.mu.Lock()
		rec, exists := r.names[m.Name]
		if exists && rec.PubB64 != m.PubKey {
			// Name already bound to a DIFFERENT key => hijack attempt.
			r.mu.Unlock()
			log.Printf("REJECT hijack: %s from %s", m.Name, src)
			reply(conn, src, errMsg("name is bound to another key"))
			return
		}
		if !exists {
			rec = &record{PubB64: m.PubKey}
			r.names[m.Name] = rec
			log.Printf("NEW name bound: %s -> key %.12s… (at %s)", m.Name, m.PubKey, src)
		}
		rec.Endpoint = src // the magic: observed source addr = live NAT mapping
		rec.LastSeen = time.Now()
		r.mu.Unlock()

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
		fresh := ok && time.Since(rec.LastSeen) < staleAfter
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
		fresh := ok && time.Since(rec.LastSeen) < staleAfter
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
		r.mu.Lock()
		for name, rec := range r.names {
			if time.Since(rec.LastSeen) > 10*staleAfter {
				delete(r.names, name)
				log.Printf("pruned dead name: %s", name)
			}
		}
		r.mu.Unlock()
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
