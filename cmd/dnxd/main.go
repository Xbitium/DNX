// dnxd: the DNX node agent. Runs on every machine.
//
// What it does:
//  1. First boot: mints an ed25519 identity (the key IS the machine)
//     and binds it to your chosen FQDN at the registry.
//  2. Heartbeats every 15s so the registry always knows the node's
//     LIVE public UDP endpoint (this also keeps the NAT mapping warm).
//  3. Answers PUNCH (fires packets at a knocking peer to open its own
//     NAT) and PING (replies with a signed PONG).
//  4. Exposes a tiny localhost HTTP control API so the `dnx` CLI can
//     say "ping computer2.internal.dnxroute.com" and get an RTT back.
//
// CRITICAL DESIGN NOTE: everything shares ONE UDP socket. The NAT
// mapping created by heartbeats is the same mapping peers punch to —
// use a second socket and hole punching silently dies.
//
// Usage (first boot):
//
//	dnxd --name computer1.internal.dnxroute.com --registry registry.dnxroute.com:4400
//
// Usage (after):
//
//	dnxd
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"dnx/internal/identity"
	"dnx/internal/proto"
	"dnx/internal/secure"
)

// agent bundles all node state.
type agent struct {
	id   *identity.Identity
	conn *net.UDPConn // the ONE shared UDP socket

	mu      sync.Mutex
	regAddr *net.UDPAddr                   // resolved registry address
	public  string                         // our own public endpoint (learned from REGISTER_ACK)
	waiters map[string]chan *proto.Message // nonce/kind -> response channel

	// ---- v0.2 session layer ----
	// One live encrypted session per peer NAME (not per address — the
	// address can change under NAT; the name and key never do).
	sessions map[string]*peerSession // peer FQDN -> session

	// ---- v0.2 tunnels: TCP carried over DNX streams ----
	tunnels *tunnelTable

	// tunnelPorts is the set of loopback ports a peer is permitted to reach.
	// Empty means inbound tunnels are refused outright.
	//
	// This is an allowlist rather than a boolean because handleTunnelOpen
	// dials whatever port the peer names. A single "tunnels on" switch would
	// hand any peer that can resolve this node a proxy to every service bound
	// to 127.0.0.1 — an admin API, a database, a metrics endpoint that was
	// only ever meant to be local.
	tunnelPorts map[int]bool
}

// parseTunnelPorts turns "22, 5432" into a set. An empty string yields an
// empty set, which disables inbound tunnels.
func parseTunnelPorts(spec string) (map[int]bool, error) {
	out := map[int]bool{}
	for _, f := range strings.Split(spec, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		n, err := strconv.Atoi(f)
		if err != nil {
			return nil, fmt.Errorf("bad port %q", f)
		}
		if n < 1 || n > 65535 {
			return nil, fmt.Errorf("port %d out of range", n)
		}
		out[n] = true
	}
	return out, nil
}

// tunnelAllowed reports why a tunnel to port is refused, or nil if permitted.
func (a *agent) tunnelAllowed(port int) error {
	if len(a.tunnelPorts) == 0 {
		return fmt.Errorf("inbound tunnels are disabled on this node")
	}
	if !a.tunnelPorts[port] {
		return fmt.Errorf("port %d is not in this node's tunnel allowlist", port)
	}
	return nil
}

// peerSession is a live encrypted channel plus what we need to rebuild it.
type peerSession struct {
	sess      *secure.Session // nil while a handshake is in flight
	eph       *secure.Ephemeral
	addr      *net.UDPAddr  // peer's current endpoint
	nonceA    string        // initiator nonce for the in-flight handshake
	done      chan struct{} // closed when the session becomes usable
	err       error
	initiator bool
}

func main() {
	name := flag.String("name", "", "this node's FQDN (first boot only), e.g. computer1.internal.dnxroute.com")
	registry := flag.String("registry", "", "registry host:port (default registry.dnxroute.com:4400)")
	api := flag.String("api", "127.0.0.1:4401", "localhost control API for the dnx CLI")
	tunnelPorts := flag.String("tunnel-ports", "",
		"comma-separated TCP ports peers may tunnel to, e.g. 22,5432 (empty disables inbound tunnels)")
	flag.Parse()

	// ---- Identity: load existing or mint on first boot ----
	allowedPorts, err := parseTunnelPorts(*tunnelPorts)
	if err != nil {
		log.Fatalf("--tunnel-ports: %v", err)
	}

	id, err := identity.LoadOrCreate(*name, *registry)
	if err != nil {
		log.Fatalf("identity: %v", err)
	}
	log.Printf("I am %s (key %.12s…)", id.Name, id.PubB64)
	log.Printf("registry: %s", id.Registry)

	// ---- The one shared UDP socket (see design note above) ----
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0}) // OS picks a port
	if err != nil {
		log.Fatalf("udp: %v", err)
	}

	a := &agent{
		id:          id,
		conn:        conn,
		waiters:     map[string]chan *proto.Message{},
		sessions:    map[string]*peerSession{}, // v0.2: encrypted channels, keyed by peer NAME
		tunnels:     newTunnelTable(),
		tunnelPorts: allowedPorts,
	}
	if len(allowedPorts) == 0 {
		log.Printf("inbound tunnels disabled (no --tunnel-ports given)")
	} else {
		log.Printf("inbound tunnels permitted to ports %v — and nothing else", *tunnelPorts)
	}
	if err := a.resolveRegistry(); err != nil {
		log.Fatalf("cannot resolve registry %s: %v", id.Registry, err)
	}

	go a.readLoop()       // dispatch every inbound packet
	go a.heartbeatLoop()  // REGISTER every 15s (keeps NAT warm + endpoint fresh)
	go a.rekeyLoop()      // v0.2: expire sessions every 5 min (forward secrecy)
	go a.tunnelTickLoop() // v0.2: drive stream retransmission timers
	a.serveAPI(*api)      // blocks: localhost HTTP for the CLI
}

// resolveRegistry turns "registry.dnxroute.com:4400" into a UDP addr.
// (Yes — the registry itself is found via legacy DNS for bootstrap.
// That's the ONLY place old-world DNS appears; everything after is DNX.)
func (a *agent) resolveRegistry() error {
	addr, err := net.ResolveUDPAddr("udp", a.id.Registry)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.regAddr = addr
	a.mu.Unlock()
	return nil
}

// ---------------------------------------------------------------------------
// Inbound packet dispatch
// ---------------------------------------------------------------------------
func (a *agent) readLoop() {
	buf := make([]byte, 64*1024)
	for {
		n, src, err := a.conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("read: %v", err)
			continue
		}
		// ---- v0.2: is this a SEALED binary frame or a v0.1 JSON control message?
		// They coexist on one socket: sealed frames start with 0xD8, JSON with '{'.
		if secure.IsSealed(buf[:n]) {
			a.handleSealed(src, append([]byte(nil), buf[:n]...))
			continue
		}

		m, err := proto.Decode(buf[:n])
		if err != nil {
			continue // not a DNX packet
		}

		switch m.Kind {

		// ---- v0.2 handshake: someone wants an encrypted channel with us ----
		case proto.KindHSInit:
			a.handleHSInit(src, m)

		case proto.KindHSResp:
			a.handleHSResp(src, m)

		case proto.KindRegisterAck:
			// Learn (and log once) our own public endpoint — STUN for free.
			a.mu.Lock()
			if a.public != m.Endpoint {
				a.public = m.Endpoint
				log.Printf("public endpoint (per registry): %s", m.Endpoint)
			}
			a.mu.Unlock()

		case proto.KindPunch:
			// Someone wants to reach us. Fire a burst at their endpoint —
			// each outbound packet opens our NAT for their inbound ones.
			peer, err := net.ResolveUDPAddr("udp", m.Endpoint)
			if err != nil {
				continue
			}
			log.Printf("PUNCH: opening path for %s (%s)", m.Name, m.Endpoint)
			for i := 0; i < 3; i++ {
				a.send(peer, &proto.Message{Kind: proto.KindPong, Name: a.id.Name, Info: "punch"})
			}

		case proto.KindPing:
			// Signed liveness probe from a peer — verify would need their
			// key (a resolve); v0.1 answers and lets the CALLER verify our
			// signed PONG instead. Echo the nonce so they can match + time it.
			resp := &proto.Message{
				Kind:  proto.KindPong,
				Name:  a.id.Name,
				Nonce: m.Nonce,
				TS:    time.Now().UnixMilli(),
			}
			resp.Sign(a.id.Priv()) // prove we hold computer2's key
			a.send(src, resp)

		case proto.KindPong, proto.KindResolveResp, proto.KindError:
			// Responses: route to whichever operation is waiting on them.
			a.deliver(m)
		}
	}
}

// deliver hands a response to the waiting operation (keyed by nonce,
// falling back to kind+target for resolve responses).
func (a *agent) deliver(m *proto.Message) {
	a.mu.Lock()
	defer a.mu.Unlock()
	keys := []string{m.Nonce, m.Kind + "|" + m.Target}
	for _, k := range keys {
		if ch, ok := a.waiters[k]; ok && k != "" && k != "|" {
			select {
			case ch <- m:
			default: // waiter already satisfied — drop duplicates
			}
			return
		}
	}
}

// wait registers interest in a response key and returns a channel.
func (a *agent) wait(key string) chan *proto.Message {
	ch := make(chan *proto.Message, 4)
	a.mu.Lock()
	a.waiters[key] = ch
	a.mu.Unlock()
	return ch
}

func (a *agent) unwait(key string) {
	a.mu.Lock()
	delete(a.waiters, key)
	a.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Heartbeat: REGISTER every 15s
// ---------------------------------------------------------------------------
func (a *agent) heartbeatLoop() {
	for {
		m := &proto.Message{
			Kind:   proto.KindRegister,
			Name:   a.id.Name,
			PubKey: a.id.PubB64,
			TS:     time.Now().UnixMilli(),
			Nonce:  newNonce(),
		}
		m.Sign(a.id.Priv())
		a.mu.Lock()
		reg := a.regAddr
		a.mu.Unlock()
		a.send(reg, m)
		time.Sleep(15 * time.Second) // < typical 30s NAT UDP timeout
	}
}

// ---------------------------------------------------------------------------
// The headline act: ping a peer BY NAME.
// resolve -> intro (punch) -> signed ping burst -> verified pong -> RTT
// ---------------------------------------------------------------------------
type pingResult struct {
	Target      string  `json:"target"`
	RTTms       float64 `json:"rtt_ms"`
	Verified    bool    `json:"identity_verified"`      // key matches the registry's name binding
	Encrypted   bool    `json:"encrypted"`              // v0.2: payload was sealed (ChaCha20-Poly1305)
	HandshakeMs float64 `json:"handshake_ms,omitempty"` // 0 on a warm session (reused)
	Error       string  `json:"error,omitempty"`
}

func (a *agent) pingByName(target string, timeout time.Duration) pingResult {
	res := pingResult{Target: target}

	// ---- Step 1: RESOLVE the name at the registry ----
	rkey := proto.KindResolveResp + "|" + target
	ch := a.wait(rkey)
	defer a.unwait(rkey)
	a.mu.Lock()
	reg := a.regAddr
	a.mu.Unlock()
	rq := &proto.Message{
		Kind: proto.KindResolve, Name: a.id.Name, Target: target,
		TS: time.Now().UnixMilli(), Nonce: newNonce(),
	}
	rq.Sign(a.id.Priv())
	a.send(reg, rq)

	var peerKey string
	var peerAddr *net.UDPAddr
	select {
	case m := <-ch:
		if m.Kind == proto.KindError {
			res.Error = m.Info
			return res
		}
		peerKey = m.PubKey
		var err error
		peerAddr, err = net.ResolveUDPAddr("udp", m.Endpoint)
		if err != nil {
			res.Error = "registry returned bad endpoint"
			return res
		}
	case <-time.After(timeout):
		res.Error = "resolve timeout (registry unreachable?)"
		return res
	}

	// ---- Step 2: INTRO — ask registry to make the peer punch back ----
	in := &proto.Message{
		Kind: proto.KindIntro, Name: a.id.Name, Target: target,
		TS: time.Now().UnixMilli(), Nonce: newNonce(),
	}
	in.Sign(a.id.Priv())
	a.send(reg, in)

	// ---- Step 3: signed PING burst until a PONG lands ----
	nonce := newNonce()
	pch := a.wait(nonce)
	defer a.unwait(nonce)

	start := time.Now()
	deadline := start.Add(timeout)
	tick := time.NewTicker(300 * time.Millisecond) // retry cadence during punch
	defer tick.Stop()

	sendPing := func() {
		p := &proto.Message{
			Kind: proto.KindPing, Name: a.id.Name, Nonce: nonce,
			TS: time.Now().UnixMilli(),
		}
		p.Sign(a.id.Priv())
		a.send(peerAddr, p)
	}
	sendPing()

	for {
		select {
		case m := <-pch:
			// ---- Step 4: verify the pong is signed by the RESOLVED key.
			// This is the DNX difference vs ICMP ping: we didn't just reach
			// "some host at an address" — we cryptographically confirmed we
			// reached the machine that OWNS the name.
			res.RTTms = float64(time.Since(start).Microseconds()) / 1000.0
			res.Verified = m.Verify(peerKey) == nil
			if !res.Verified {
				res.Error = "pong signature did not match resolved identity (spoofing?)"
			}
			return res
		case <-tick.C:
			if time.Now().After(deadline) {
				res.Error = "ping timeout (peer offline or NAT unpunchable — v0.2 adds relay fallback)"
				return res
			}
			sendPing() // keep punching
		}
	}
}

// ---------------------------------------------------------------------------
// Localhost control API (for the dnx CLI)
// ---------------------------------------------------------------------------
func (a *agent) serveAPI(listen string) {
	mux := http.NewServeMux()

	// GET /ping?name=<fqdn> -> v0.2 ENCRYPTED ping (handshake + sealed payload)
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("name")
		if target == "" {
			http.Error(w, `missing ?name=<fqdn>`, http.StatusBadRequest)
			return
		}
		writeJSON(w, a.pingEncrypted(target, 12*time.Second))
	})

	// GET /ping-plain?name=<fqdn> -> v0.1 signed-but-plaintext ping.
	// Kept so we can tcpdump both and SEE the difference on the wire.
	mux.HandleFunc("/ping-plain", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("name")
		if target == "" {
			http.Error(w, `missing ?name=<fqdn>`, http.StatusBadRequest)
			return
		}
		writeJSON(w, a.pingByName(target, 8*time.Second))
	})

	// GET /status -> who am I, where am I, who do I trust
	// POST /tunnel?name=<fqdn>&local=<port>&remote=<port>
	// Opens a local TCP listener whose traffic rides DNX to the peer.
	mux.HandleFunc("/tunnel", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		var local, remote int
		fmt.Sscanf(r.URL.Query().Get("local"), "%d", &local)
		fmt.Sscanf(r.URL.Query().Get("remote"), "%d", &remote)
		if name == "" || local == 0 || remote == 0 {
			writeJSON(w, map[string]string{"error": "need ?name=<fqdn>&local=<port>&remote=<port>"})
			return
		}
		if err := a.serveTunnel(name, local, remote); err != nil {
			writeJSON(w, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{
			"listening": fmt.Sprintf("127.0.0.1:%d", local),
			"peer":      name,
			"peer_port": remote,
		})
	})

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		pub := a.public
		a.mu.Unlock()
		writeJSON(w, map[string]string{
			"name":            a.id.Name,
			"pubkey":          a.id.PubB64,
			"registry":        a.id.Registry,
			"public_endpoint": pub, // shown here for debugging ONLY — users live in names
		})
	})

	log.Printf("control API on http://%s (dnx CLI talks here)", listen)
	log.Fatal(http.ListenAndServe(listen, mux))
}

// ---- tiny helpers ----

func (a *agent) send(to *net.UDPAddr, m *proto.Message) {
	a.conn.WriteToUDP(proto.Encode(m), to)
}

func newNonce() string {
	b := make([]byte, 12)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(w, `{"error":%q}`, err.Error())
	}
}
