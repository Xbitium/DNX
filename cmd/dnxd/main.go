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
//   dnxd --name computer1.internal.dnxroute.com --registry registry.dnxroute.com:4400
// Usage (after):
//   dnxd
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
	"sync"
	"time"

	"dnx/internal/identity"
	"dnx/internal/proto"
	"dnx/internal/secure"
)

type agent struct {
	id   *identity.Identity
	conn *net.UDPConn

	mu      sync.Mutex
	regAddr *net.UDPAddr
	public  string
	waiters map[string]chan *proto.Message

	// One live encrypted session per peer NAME (not per address — the
	// address can change under NAT; the name and key never do).
	sessions map[string]*peerSession
}

type peerSession struct {
	sess      *secure.Session
	eph       *secure.Ephemeral
	addr      *net.UDPAddr
	nonceA    string
	done      chan struct{}
	err       error
	initiator bool
}

func main() {
	name := flag.String("name", "", "this node's FQDN (first boot only), e.g. computer1.internal.dnxroute.com")
	registry := flag.String("registry", "", "registry host:port (default registry.dnxroute.com:4400)")
	api := flag.String("api", "127.0.0.1:4401", "localhost control API for the dnx CLI")
	flag.Parse()

	id, err := identity.LoadOrCreate(*name, *registry)
	if err != nil {
		log.Fatalf("identity: %v", err)
	}
	log.Printf("I am %s (key %.12s…)", id.Name, id.PubB64)
	log.Printf("registry: %s", id.Registry)

	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		log.Fatalf("udp: %v", err)
	}

	a := &agent{
		id:       id,
		conn:     conn,
		waiters:  map[string]chan *proto.Message{},
		sessions: map[string]*peerSession{},
	}
	if err := a.resolveRegistry(); err != nil {
		log.Fatalf("cannot resolve registry %s: %v", id.Registry, err)
	}

	go a.readLoop()
	go a.heartbeatLoop()
	go a.rekeyLoop()
	a.serveAPI(*api)
}

// resolveRegistry turns "registry.dnxroute.com:4400" into a UDP addr.
// The registry itself is found via legacy DNS for bootstrap — the ONLY
// place old-world DNS appears; everything after is DNX.
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

func (a *agent) readLoop() {
	buf := make([]byte, 64*1024)
	for {
		n, src, err := a.conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("read: %v", err)
			continue
		}
		if secure.IsSealed(buf[:n]) {
			a.handleSealed(src, append([]byte(nil), buf[:n]...))
			continue
		}

		m, err := proto.Decode(buf[:n])
		if err != nil {
			continue
		}

		switch m.Kind {

		case proto.KindHSInit:
			a.handleHSInit(src, m)

		case proto.KindHSResp:
			a.handleHSResp(src, m)

		case proto.KindRegisterAck:
			a.mu.Lock()
			if a.public != m.Endpoint {
				a.public = m.Endpoint
				log.Printf("public endpoint (per registry): %s", m.Endpoint)
			}
			a.mu.Unlock()

		case proto.KindPunch:
			peer, err := net.ResolveUDPAddr("udp", m.Endpoint)
			if err != nil {
				continue
			}
			log.Printf("PUNCH: opening path for %s (%s)", m.Name, m.Endpoint)
			for i := 0; i < 3; i++ {
				a.send(peer, &proto.Message{Kind: proto.KindPong, Name: a.id.Name, Info: "punch"})
			}

		case proto.KindPing:
			resp := &proto.Message{
				Kind:  proto.KindPong,
				Name:  a.id.Name,
				Nonce: m.Nonce,
				TS:    time.Now().UnixMilli(),
			}
			resp.Sign(a.id.Priv())
			a.send(src, resp)

		case proto.KindPong, proto.KindResolveResp, proto.KindError:
			a.deliver(m)
		}
	}
}

func (a *agent) deliver(m *proto.Message) {
	a.mu.Lock()
	defer a.mu.Unlock()
	keys := []string{m.Nonce, m.Kind + "|" + m.Target}
	for _, k := range keys {
		if ch, ok := a.waiters[k]; ok && k != "" && k != "|" {
			select {
			case ch <- m:
			default:
			}
			return
		}
	}
}

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
		time.Sleep(15 * time.Second)
	}
}

// The headline act: ping a peer BY NAME.
// resolve -> intro (punch) -> signed ping burst -> verified pong -> RTT
type pingResult struct {
	Target      string  `json:"target"`
	RTTms       float64 `json:"rtt_ms"`
	Verified    bool    `json:"identity_verified"`
	Encrypted   bool    `json:"encrypted"`
	HandshakeMs float64 `json:"handshake_ms,omitempty"`
	Error       string  `json:"error,omitempty"`
}

func (a *agent) pingByName(target string, timeout time.Duration) pingResult {
	res := pingResult{Target: target}

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

	in := &proto.Message{
		Kind: proto.KindIntro, Name: a.id.Name, Target: target,
		TS: time.Now().UnixMilli(), Nonce: newNonce(),
	}
	in.Sign(a.id.Priv())
	a.send(reg, in)

	nonce := newNonce()
	pch := a.wait(nonce)
	defer a.unwait(nonce)

	start := time.Now()
	deadline := start.Add(timeout)
	tick := time.NewTicker(300 * time.Millisecond)
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
			sendPing()
		}
	}
}

func (a *agent) serveAPI(listen string) {
	mux := http.NewServeMux()

	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("name")
		if target == "" {
			http.Error(w, `missing ?name=<fqdn>`, http.StatusBadRequest)
			return
		}
		writeJSON(w, a.pingEncrypted(target, 12*time.Second))
	})

	// v0.1 signed-but-plaintext ping, kept so we can tcpdump both and SEE
	// the difference on the wire.
	mux.HandleFunc("/ping-plain", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("name")
		if target == "" {
			http.Error(w, `missing ?name=<fqdn>`, http.StatusBadRequest)
			return
		}
		writeJSON(w, a.pingByName(target, 8*time.Second))
	})

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		pub := a.public
		a.mu.Unlock()
		writeJSON(w, map[string]string{
			"name":            a.id.Name,
			"pubkey":          a.id.PubB64,
			"registry":        a.id.Registry,
			"public_endpoint": pub,
		})
	})

	log.Printf("control API on http://%s (dnx CLI talks here)", listen)
	log.Fatal(http.ListenAndServe(listen, mux))
}

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
