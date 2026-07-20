// dnx-routerd: a DISTRIBUTED DNX router. One process per node, forwarding
// sealed frames to the next hop over the real internet, by 256-bit name
// address — never by reading the payload.
//
// Unlike the single-process PoC, this is the honest article: each daemon
// holds ONE router's field table, receives frames over UDP, matches its
// 64-bit field, and forwards to the next hop's real endpoint (the overlay
// underlay, labeled as such). A packet physically crosses machines.
//
// Each daemon also emits a live TELEMETRY event per forwarding decision to
// an HTTP stream, so the dashboard can show real hops as they happen.
//
// Config is a small JSON file describing this node's routers and links.
// Usage: dnx-routerd --config node.json --listen :4500 --telemetry :4600
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"dnx/internal/dnxaddr"
)

// ---------------------------------------------------------------------------
// Wire frame for the distributed router.
//
//	[1B magic 0xDF][32B DNX address][2B consumed-depth][payload...]
//
// consumed-depth = how many tiers upstream routers have already resolved,
// so the receiving daemon knows which field to read next. This is the
// on-the-wire equivalent of "mark_resolved" from the concept doc.
// The payload is itself a sealed ChaCha20 frame (0xD8) — routers never open it.
// ---------------------------------------------------------------------------
const routeMagic = 0xDF

type routedFrame struct {
	addr     dnxaddr.Addr
	consumed int
	payload  []byte // opaque sealed bytes
}

func decodeFrame(b []byte) (*routedFrame, error) {
	if len(b) < 1+32+2 || b[0] != routeMagic {
		return nil, fmt.Errorf("not a DNX routed frame")
	}
	var f routedFrame
	for i := 0; i < 4; i++ {
		f.addr.Field[i] = binary.BigEndian.Uint64(b[1+i*8:])
	}
	f.consumed = int(binary.BigEndian.Uint16(b[33:]))
	f.payload = b[35:]
	return &f, nil
}

func (f *routedFrame) encode() []byte {
	b := make([]byte, 35+len(f.payload))
	b[0] = routeMagic
	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint64(b[1+i*8:], f.addr.Field[i])
	}
	binary.BigEndian.PutUint16(b[33:], uint16(f.consumed))
	copy(b[35:], f.payload)
	return b
}

// ---------------------------------------------------------------------------
// Node configuration
// ---------------------------------------------------------------------------

// routerCfg is one router hosted by this daemon.
type routerCfg struct {
	Name    string            `json:"name"`
	Depth   int               `json:"depth"`   // 0=TLD..3=host — which field it matches
	Entries map[string]string `json:"entries"` // hex64 field value -> next-hop label
}

// nodeCfg is this daemon's whole config.
type nodeCfg struct {
	Node     string               `json:"node"`     // this box's label, e.g. "dnxroute1"
	Routers  []routerCfg          `json:"routers"`  // routers hosted here (in resolution order)
	Hops     map[string]string    `json:"hops"`     // next-hop label -> "ip:port" (or ":local"/":deliver")
	Firsthop string               `json:"firsthop"` // which local router a fresh packet enters at
}

// ---------------------------------------------------------------------------
// Daemon
// ---------------------------------------------------------------------------

type daemon struct {
	cfg     nodeCfg
	conn    *net.UDPConn
	routers map[int]*routerCfg // depth -> router hosted here

	mu     sync.Mutex
	events []event // ring buffer of recent telemetry for the dashboard
}

type event struct {
	TS       int64  `json:"ts"`
	Node     string `json:"node"`
	Router   string `json:"router"`
	Field    string `json:"field"`
	Value    string `json:"value"`
	NextHop  string `json:"next_hop"`
	Action   string `json:"action"` // "forward" | "deliver" | "drop"
	Detail   string `json:"detail"`
}

func main() {
	cfgPath := flag.String("config", "node.json", "node config file")
	listen := flag.String("listen", ":4500", "UDP listen address for routed frames")
	telem := flag.String("telemetry", ":4600", "HTTP telemetry/dashboard API")
	flag.Parse()

	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	var cfg nodeCfg
	if err := json.Unmarshal(raw, &cfg); err != nil {
		log.Fatalf("config parse: %v", err)
	}

	addr, _ := net.ResolveUDPAddr("udp", *listen)
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	d := &daemon{cfg: cfg, conn: conn, routers: map[int]*routerCfg{}}
	for i := range cfg.Routers {
		r := &cfg.Routers[i]
		d.routers[r.Depth] = r
	}

	log.Printf("dnx-routerd up: node=%s, hosting %d router(s), listen=%s", cfg.Node, len(cfg.Routers), *listen)
	for _, r := range cfg.Routers {
		log.Printf("  router %q matches %s field (depth %d), %d entries", r.Name, dnxaddr.FieldName(r.Depth), r.Depth, len(r.Entries))
	}

	go d.serveTelemetry(*telem)
	d.readLoop()
}

// readLoop receives routed frames and forwards them hop by hop through the
// routers hosted on THIS node, then out to the next node.
func (d *daemon) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, src, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		f, err := decodeFrame(buf[:n])
		if err != nil {
			continue
		}
		d.route(f, src)
	}
}

// route walks the frame through every local router whose depth is next,
// emitting telemetry, until it must leave this node (forward to another box),
// deliver, or drop.
func (d *daemon) route(f *routedFrame, src *net.UDPAddr) {
	for {
		r, hosted := d.routers[f.consumed]
		if !hosted {
			// The tier this frame needs isn't handled here. Shouldn't happen if
			// links are correct; drop with telemetry.
			d.emit(event{Node: d.cfg.Node, Action: "drop", Detail: fmt.Sprintf("no local router for depth %d", f.consumed)})
			return
		}

		field := f.addr.FieldAt(r.Depth)
		key := hex64(field)
		nextLabel, ok := r.Entries[key]

		if !ok {
			d.emit(event{
				Node: d.cfg.Node, Router: r.Name, Field: dnxaddr.FieldName(r.Depth),
				Value: key, Action: "drop",
				Detail: r.Name + " is authoritative for " + dnxaddr.FieldName(r.Depth) + "; no route for " + key,
			})
			return
		}

		// Resolve where this next-hop label points.
		dest, known := d.cfg.Hops[nextLabel]
		if !known {
			d.emit(event{Node: d.cfg.Node, Router: r.Name, Action: "drop", Detail: "unknown hop label " + nextLabel})
			return
		}

		f.consumed++ // this tier is now resolved

		switch dest {
		case ":deliver", ":local":
			d.emit(event{
				Node: d.cfg.Node, Router: r.Name, Field: dnxaddr.FieldName(r.Depth),
				Value: key, NextHop: nextLabel, Action: "deliver",
				Detail: "matched " + dnxaddr.FieldName(r.Depth) + "; delivered on " + d.cfg.Node,
			})
			return

		case ":localnext":
			// Next tier is handled by another router on THIS same node.
			if _, ok := d.routers[f.consumed]; !ok {
				d.emit(event{Node: d.cfg.Node, Router: r.Name, Action: "drop",
					Detail: fmt.Sprintf("localnext but no router at depth %d", f.consumed)})
				return
			}
			d.emit(event{
				Node: d.cfg.Node, Router: r.Name, Field: dnxaddr.FieldName(r.Depth),
				Value: key, NextHop: nextLabel, Action: "forward",
				Detail: "matched " + dnxaddr.FieldName(r.Depth) + " -> next tier on same node",
			})
			continue // loop to the next local router

		default:
			// Remote: send across the internet to the next daemon's ip:port.
			d.emit(event{
				Node: d.cfg.Node, Router: r.Name, Field: dnxaddr.FieldName(r.Depth),
				Value: key, NextHop: nextLabel, Action: "forward",
				Detail: "matched " + dnxaddr.FieldName(r.Depth) + " -> " + nextLabel + " @ " + dest + " (CROSS-INTERNET)",
			})
			d.sendTo(dest, f)
			return
		}
	}
}

func (d *daemon) sendTo(dest string, f *routedFrame) {
	addr, err := net.ResolveUDPAddr("udp", dest)
	if err != nil {
		return
	}
	d.conn.WriteToUDP(f.encode(), addr)
}


func hex64(v uint64) string {
	const h = "0123456789abcdef"
	var b [16]byte
	for i := 15; i >= 0; i-- {
		b[i] = h[v&0xF]
		v >>= 4
	}
	return "0x" + string(b[:])
}

// ---------------------------------------------------------------------------
// Telemetry ring buffer + HTTP API for the dashboard
// ---------------------------------------------------------------------------

func (d *daemon) emit(e event) {
	e.TS = time.Now().UnixMilli()
	log.Printf("[%s/%s] %s %s %s -> %s (%s)", e.Node, e.Router, e.Action, e.Field, e.Value, e.NextHop, e.Detail)
	d.mu.Lock()
	d.events = append(d.events, e)
	if len(d.events) > 200 {
		d.events = d.events[len(d.events)-200:]
	}
	d.mu.Unlock()
}

func (d *daemon) serveTelemetry(listen string) {
	mux := http.NewServeMux()

	// CORS so the dashboard (served from the site) can poll any node.
	cors := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			h(w, r)
		}
	}

	// GET /events?since=<ts> -> telemetry newer than ts
	mux.HandleFunc("/events", cors(func(w http.ResponseWriter, r *http.Request) {
		var since int64
		fmt.Sscanf(r.URL.Query().Get("since"), "%d", &since)
		d.mu.Lock()
		var out []event
		for _, e := range d.events {
			if e.TS > since {
				out = append(out, e)
			}
		}
		d.mu.Unlock()
		writeJSON(w, map[string]any{"node": d.cfg.Node, "events": out})
	}))

	// POST /inject -> originate a packet at this node (dashboard "send" button).
	// body: {"name":"host1.disa.dnxroute.com"}  — resolved to a 256-bit addr here.
	mux.HandleFunc("/inject", cors(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Name string `json:"name"` }
		json.NewDecoder(r.Body).Decode(&body)
		reg := dnxaddr.NewRegistry()
		a, err := reg.FromName(body.Name)
		if err != nil {
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		// A fake sealed payload (0xD8) — routers never open it.
		payload := append([]byte{0xD8}, []byte("sealed-demo-payload")...)
		f := &routedFrame{addr: a, consumed: 0, payload: payload}
		d.emit(event{Node: d.cfg.Node, Action: "inject", Detail: body.Name + " = " + a.String(), Value: a.String()})
		d.route(f, nil)
		writeJSON(w, map[string]any{"injected": body.Name, "address": a.String()})
	}))

	// GET /topology -> this node's routers and links, for the dashboard diagram.
	mux.HandleFunc("/topology", cors(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, d.cfg)
	}))

	log.Printf("telemetry API on %s", listen)
	http.ListenAndServe(listen, mux)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
