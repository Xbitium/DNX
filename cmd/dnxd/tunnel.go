// tunnel.go — carrying real TCP traffic over DNX.
//
// This is the point of everything below it: a local TCP listener whose
// bytes travel as DNX stream frames, sealed by the v0.2 session layer,
// addressed by name, across NAT, to a port on the peer.
//
//	dnx tunnel host1.dnx.dnxroute.com 2222:22
//	ssh -p 2222 user@localhost      <-- rides DNX end to end
//
// LAYERING (each layer only knows the one below):
//
//	TCP app (ssh)
//	  └─ internal/stream   reliability + ordering        (stream frames)
//	      └─ internal/secure   ChaCha20-Poly1305 seal    (sealed frames)
//	          └─ UDP/IP        NAT-punched datagrams
//
// MULTIPLEXING: one sealed session can carry many tunnels, so each stream
// gets a 32-bit id. The opener picks the id; ids are scoped to the session.
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"dnx/internal/stream"
)

// Sealed-payload discriminator. JSON control payloads start with '{' (0x7B),
// so a distinct first byte lets stream data share the same sealed channel
// without ambiguity — the same trick that lets sealed frames coexist with
// v0.1 JSON on one UDP socket.
const payloadStream = 0x02

// tunnelStream is one live TCP connection carried over DNX.
type tunnelStream struct {
	id     uint32
	peer   string // peer FQDN
	stream *stream.Stream
	conn   net.Conn // the local TCP side
	done   chan struct{}
	once   sync.Once
}

func (t *tunnelStream) close() {
	t.once.Do(func() {
		close(t.done)
		if t.conn != nil {
			t.conn.Close()
		}
		if t.stream != nil {
			t.stream.Close()
		}
	})
}

// ---------------------------------------------------------------------------
// Agent-side registry of active tunnels
// ---------------------------------------------------------------------------

type tunnelTable struct {
	mu      sync.Mutex
	streams map[uint32]*tunnelStream
	nextID  uint32
}

func newTunnelTable() *tunnelTable {
	return &tunnelTable{streams: map[uint32]*tunnelStream{}}
}

func (tt *tunnelTable) add(t *tunnelStream) {
	tt.mu.Lock()
	tt.streams[t.id] = t
	tt.mu.Unlock()
}

func (tt *tunnelTable) get(id uint32) *tunnelStream {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	return tt.streams[id]
}

func (tt *tunnelTable) remove(id uint32) {
	tt.mu.Lock()
	delete(tt.streams, id)
	tt.mu.Unlock()
}

func (tt *tunnelTable) allocID() uint32 {
	return atomic.AddUint32(&tt.nextID, 1)
}

// tickAll drives retransmission for every live stream, and reaps dead ones.
func (tt *tunnelTable) tickAll() {
	tt.mu.Lock()
	live := make([]*tunnelStream, 0, len(tt.streams))
	for _, t := range tt.streams {
		live = append(live, t)
	}
	tt.mu.Unlock()

	for _, t := range live {
		if !t.stream.Tick() {
			log.Printf("tunnel %d to %s: stream died, closing", t.id, t.peer)
			t.close()
			tt.remove(t.id)
		}
	}
}

// ---------------------------------------------------------------------------
// Wire helpers: stream frames inside sealed payloads
// ---------------------------------------------------------------------------

// encodeStreamPayload builds  [0x02][4B stream id][stream frame].
func encodeStreamPayload(id uint32, frame []byte) []byte {
	b := make([]byte, 5+len(frame))
	b[0] = payloadStream
	binary.BigEndian.PutUint32(b[1:], id)
	copy(b[5:], frame)
	return b
}

func decodeStreamPayload(b []byte) (uint32, []byte, bool) {
	if len(b) < 5 || b[0] != payloadStream {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(b[1:5]), b[5:], true
}

// ---------------------------------------------------------------------------
// Opening a tunnel (client side)
// ---------------------------------------------------------------------------

// serveTunnel listens on a local TCP port and pipes every accepted
// connection to `remotePort` on the named peer, over DNX.
func (a *agent) serveTunnel(peerName string, localPort, remotePort int) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		return fmt.Errorf("cannot listen on port %d: %w", localPort, err)
	}
	log.Printf("tunnel listening on 127.0.0.1:%d -> %s:%d (over DNX)", localPort, peerName, remotePort)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Printf("tunnel accept failed: %v", err)
				return
			}
			go a.openTunnelStream(peerName, remotePort, conn)
		}
	}()
	return nil
}

// openTunnelStream establishes one DNX stream for one accepted TCP connection.
func (a *agent) openTunnelStream(peerName string, remotePort int, conn net.Conn) {
	// Ensure we have a live encrypted session with the peer first — the
	// tunnel inherits its identity guarantees from that handshake.
	peerKey, peerAddr, err := a.resolve(peerName, 12*time.Second)
	if err != nil {
		log.Printf("tunnel: cannot resolve %s: %v", peerName, err)
		conn.Close()
		return
	}
	a.intro(peerName)
	sess, err := a.getSession(peerName, peerKey, peerAddr, 12*time.Second)
	if err != nil {
		log.Printf("tunnel: no session with %s: %v", peerName, err)
		conn.Close()
		return
	}
	if sess.PeerIDKey != peerKey {
		log.Printf("tunnel: REFUSING %s — session key does not match the registry binding", peerName)
		conn.Close()
		return
	}

	id := a.tunnels.allocID()

	a.mu.Lock()
	addr := a.sessions[peerName].addr
	a.mu.Unlock()

	ts := &tunnelStream{id: id, peer: peerName, conn: conn, done: make(chan struct{})}
	ts.stream = stream.New(func(f []byte) {
		a.conn.WriteToUDP(sess.Seal(encodeStreamPayload(id, f)), addr)
	})
	a.tunnels.add(ts)

	// Ask the peer to connect the far end to remotePort.
	open, _ := json.Marshal(sealedPayload{
		Kind: "OPEN", Name: a.id.Name, SID: id, Port: remotePort,
	})
	a.conn.WriteToUDP(sess.Seal(open), addr)

	log.Printf("tunnel %d: opening %s:%d over DNX", id, peerName, remotePort)
	a.pipe(ts)
}

// ---------------------------------------------------------------------------
// Accepting a tunnel (server side)
// ---------------------------------------------------------------------------

// handleTunnelOpen is called when a peer asks us to connect a local port.
func (a *agent) handleTunnelOpen(peerName string, p sealedPayload, seal func([]byte) []byte, addr *net.UDPAddr) {
	// SECURITY: only ports on this machine's loopback are reachable, and only
	// if the operator allowed tunneling. A peer cannot use us as a general
	// proxy to third parties.
	if !a.tunnelServe {
		log.Printf("tunnel: REFUSED open from %s (tunnel serving disabled; start dnxd with --allow-tunnel)", peerName)
		resp, _ := json.Marshal(sealedPayload{Kind: "OPENERR", Name: a.id.Name, SID: p.SID,
			Info: "tunnel serving disabled on this node"})
		a.conn.WriteToUDP(seal(resp), addr)
		return
	}

	target := fmt.Sprintf("127.0.0.1:%d", p.Port)
	conn, err := net.DialTimeout("tcp", target, 8*time.Second)
	if err != nil {
		log.Printf("tunnel: cannot reach %s for %s: %v", target, peerName, err)
		resp, _ := json.Marshal(sealedPayload{Kind: "OPENERR", Name: a.id.Name, SID: p.SID,
			Info: err.Error()})
		a.conn.WriteToUDP(seal(resp), addr)
		return
	}

	ts := &tunnelStream{id: p.SID, peer: peerName, conn: conn, done: make(chan struct{})}
	ts.stream = stream.New(func(f []byte) {
		a.conn.WriteToUDP(seal(encodeStreamPayload(p.SID, f)), addr)
	})
	a.tunnels.add(ts)

	log.Printf("tunnel %d: accepted from %s -> %s", p.SID, peerName, target)
	resp, _ := json.Marshal(sealedPayload{Kind: "OPENOK", Name: a.id.Name, SID: p.SID})
	a.conn.WriteToUDP(seal(resp), addr)

	go a.pipe(ts)
}

// ---------------------------------------------------------------------------
// The pipe: TCP <-> DNX stream, both directions
// ---------------------------------------------------------------------------

func (a *agent) pipe(ts *tunnelStream) {
	defer func() {
		ts.close()
		a.tunnels.remove(ts.id)
		log.Printf("tunnel %d: closed", ts.id)
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// TCP -> DNX
	go func() {
		defer wg.Done()
		if _, err := io.Copy(ts.stream, ts.conn); err != nil {
			// Normal on close; only interesting while debugging.
			log.Printf("tunnel %d: tcp->dnx ended: %v", ts.id, err)
		}
		ts.stream.Close()
	}()

	// DNX -> TCP
	go func() {
		defer wg.Done()
		if _, err := io.Copy(ts.conn, ts.stream); err != nil && err != io.EOF {
			log.Printf("tunnel %d: dnx->tcp ended: %v", ts.id, err)
		}
		if c, ok := ts.conn.(*net.TCPConn); ok {
			c.CloseWrite()
		}
	}()

	wg.Wait()
}

// tunnelTickLoop drives retransmission for every live stream.
// 25ms is comfortably below the 200ms minimum RTO, so a lost segment is
// detected promptly without busy-looping.
func (a *agent) tunnelTickLoop() {
	for range time.Tick(25 * time.Millisecond) {
		a.tunnels.tickAll()
	}
}
