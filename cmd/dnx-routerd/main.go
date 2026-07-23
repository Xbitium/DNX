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
	"strconv"
	"sync"
	"time"

	"dnx/internal/dnxaddr"
	"dnx/internal/nspath"
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
const (
	routeMagic = 0xDF // fixed four-field address (the original format)
	pathMagic  = 0xDE // variable-length namespace path (DNXP-0001)
)

// destination is whatever a frame carries as its target. The two formats
// differ only in how a level is read and which table answers for it; the walk
// itself — read one level, look it up, forward, never look lower — is the
// same, which is what makes running both at once tolerable rather than a
// second implementation of the routing logic.
type destination interface {
	// keyAt returns the forwarding-table key for the given level.
	keyAt(depth int) (string, bool)
	// tableFor returns the table this format consults on a given router.
	tableFor(r *routerCfg) map[string]string
	// encode renders the frame for the next hop.
	encode(consumed int, payload []byte) []byte
	// format names the wire format, for telemetry.
	format() string
}

// ---- fixed four-field address ----

type fixedDest struct{ addr dnxaddr.Addr }

func (d fixedDest) keyAt(depth int) (string, bool) {
	if depth < 0 || depth > 3 {
		return "", false
	}
	return hex64(d.addr.FieldAt(depth)), true
}
func (d fixedDest) tableFor(r *routerCfg) map[string]string { return r.Entries }
func (d fixedDest) format() string                          { return "fixed-address" }
func (d fixedDest) encode(consumed int, payload []byte) []byte {
	b := make([]byte, 35+len(payload))
	b[0] = routeMagic
	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint64(b[1+i*8:], d.addr.Field[i])
	}
	binary.BigEndian.PutUint16(b[33:], uint16(consumed))
	copy(b[35:], payload)
	return b
}

// ---- variable-length namespace path (DNXP-0001) ----

type pathDest struct{ path nspath.Path }

func (d pathDest) keyAt(depth int) (string, bool) {
	nid, ok := d.path.At(depth)
	if !ok {
		return "", false
	}
	return strconv.FormatUint(uint64(nid), 10), true
}
func (d pathDest) tableFor(r *routerCfg) map[string]string { return r.NIDs }
func (d pathDest) format() string                          { return "namespace-path" }
func (d pathDest) encode(consumed int, payload []byte) []byte {
	enc, err := d.path.Encode()
	if err != nil {
		return nil
	}
	b := make([]byte, 1+len(enc)+2+len(payload))
	b[0] = pathMagic
	copy(b[1:], enc)
	binary.BigEndian.PutUint16(b[1+len(enc):], uint16(consumed))
	copy(b[1+len(enc)+2:], payload)
	return b
}

// decodeAny parses either wire format, distinguished by the first byte.
func decodeAny(b []byte) (destination, int, []byte, error) {
	if len(b) < 1 {
		return nil, 0, nil, fmt.Errorf("empty frame")
	}
	switch b[0] {
	case routeMagic:
		if len(b) < 1+32+2 {
			return nil, 0, nil, fmt.Errorf("truncated fixed-address frame")
		}
		var a dnxaddr.Addr
		for i := 0; i < 4; i++ {
			a.Field[i] = binary.BigEndian.Uint64(b[1+i*8:])
		}
		return fixedDest{addr: a}, int(binary.BigEndian.Uint16(b[33:])), b[35:], nil

	case pathMagic:
		if len(b) < 2 {
			return nil, 0, nil, fmt.Errorf("truncated path frame")
		}
		p, err := nspath.Decode(b[1:])
		if err != nil {
			return nil, 0, nil, fmt.Errorf("path frame: %w", err)
		}
		encLen := nspath.EncodedLen(p.Depth())
		if len(b) < 1+encLen+2 {
			return nil, 0, nil, fmt.Errorf("truncated path frame")
		}
		return pathDest{path: p}, int(binary.BigEndian.Uint16(b[1+encLen:])), b[1+encLen+2:], nil
	}
	return nil, 0, nil, fmt.Errorf("unrecognised frame marker 0x%02X", b[0])
}

// ---------------------------------------------------------------------------
// Node configuration
// ---------------------------------------------------------------------------

// routerCfg is one router hosted by this daemon.
type routerCfg struct {
	Name  string `json:"name"`
	Depth int    `json:"depth"` // which level of the destination this router reads

	// Entries answers for the fixed four-field address: hex64 value -> hop.
	Entries map[string]string `json:"entries"`
	// NIDs answers for a namespace path: decimal identifier -> hop.
	// A router may serve both while the two formats run side by side.
	NIDs map[string]string `json:"nids"`
}

// nodeCfg is this daemon's whole config.
type nodeCfg struct {
	Node     string            `json:"node"`     // this box's label, e.g. "dnxroute1"
	Routers  []routerCfg       `json:"routers"`  // routers hosted here (in resolution order)
	Hops     map[string]string `json:"hops"`     // next-hop label -> "ip:port" (or ":local"/":deliver")
	Firsthop string            `json:"firsthop"` // which local router a fresh packet enters at

	// Namespace lists the names this node allocates paths for, in order.
	// Allocation is deterministic, so every node that lists the same names in
	// the same order derives the same paths — which is what lets a static
	// topology use them before the registry hands them out.
	Namespace []string `json:"namespace"`
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

	// ns allocates namespace paths for the names this node knows about.
	// Allocation is deterministic, so every node listing the same names in
	// the same order derives identical paths.
	ns *nspath.Tree
}

type event struct {
	TS      int64  `json:"ts"`
	Node    string `json:"node"`
	Router  string `json:"router"`
	Field   string `json:"field"`
	Value   string `json:"value"`
	NextHop string `json:"next_hop"`
	Action  string `json:"action"` // "forward" | "deliver" | "drop"
	Detail  string `json:"detail"`
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

	d := &daemon{cfg: cfg, conn: conn, routers: map[int]*routerCfg{}, ns: nspath.NewTree()}
	for _, n := range cfg.Namespace {
		p, err := d.ns.Allocate(n)
		if err != nil {
			log.Fatalf("namespace %q: %v", n, err)
		}
		log.Printf("  namespace %s -> [%s] (%d bytes on the wire, vs 32 fixed)",
			n, p.String(), nspath.EncodedLen(p.Depth()))
	}
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
		dest, consumed, payload, err := decodeAny(buf[:n])
		if err != nil {
			continue
		}
		d.route(dest, consumed, payload, src)
	}
}

// route walks the frame through every local router whose depth is next,
// emitting telemetry, until it must leave this node (forward to another box),
// deliver, or drop.
// route walks a destination through the routers hosted on this node,
// emitting telemetry, until the frame must leave, deliver, or drop.
//
// The walk is identical for both wire formats: read the one level this router
// owns, look it up, forward. Only the lookup key and the table differ, which
// is the whole reason both can run at once without a second copy of this
// logic — and the reason the migration can be gradual rather than a flag day.
func (d *daemon) route(dest destination, consumed int, payload []byte, src *net.UDPAddr) {
	for {
		r, hosted := d.routers[consumed]
		if !hosted {
			d.emit(event{Node: d.cfg.Node, Action: "drop",
				Detail: fmt.Sprintf("no local router for level %d (%s)", consumed, dest.format())})
			return
		}

		key, ok := dest.keyAt(r.Depth)
		if !ok {
			d.emit(event{Node: d.cfg.Node, Router: r.Name, Action: "drop",
				Detail: fmt.Sprintf("destination has no level %d", r.Depth)})
			return
		}

		table := dest.tableFor(r)
		nextLabel, known := table[key]
		if !known {
			d.emit(event{
				Node: d.cfg.Node, Router: r.Name, Field: dnxaddr.FieldName(r.Depth),
				Value: key, Action: "drop",
				Detail: r.Name + " is authoritative for level " + strconv.Itoa(r.Depth) +
					"; no route for " + key + " (" + dest.format() + ")",
			})
			return
		}

		hop, hopKnown := d.cfg.Hops[nextLabel]
		if !hopKnown {
			d.emit(event{Node: d.cfg.Node, Router: r.Name, Action: "drop",
				Detail: "unknown hop label " + nextLabel})
			return
		}

		consumed++

		switch hop {
		case ":deliver", ":local":
			d.emit(event{
				Node: d.cfg.Node, Router: r.Name, Field: dnxaddr.FieldName(r.Depth),
				Value: key, NextHop: nextLabel, Action: "deliver",
				Detail: "matched level " + strconv.Itoa(r.Depth) + " (" + dest.format() + "); delivered on " + d.cfg.Node,
			})
			return

		case ":localnext":
			if _, ok := d.routers[consumed]; !ok {
				d.emit(event{Node: d.cfg.Node, Router: r.Name, Action: "drop",
					Detail: fmt.Sprintf("localnext but no router for level %d", consumed)})
				return
			}
			d.emit(event{
				Node: d.cfg.Node, Router: r.Name, Field: dnxaddr.FieldName(r.Depth),
				Value: key, NextHop: nextLabel, Action: "forward",
				Detail: "matched level " + strconv.Itoa(r.Depth) + " (" + dest.format() + ") -> next level on same node",
			})
			continue

		default:
			d.emit(event{
				Node: d.cfg.Node, Router: r.Name, Field: dnxaddr.FieldName(r.Depth),
				Value: key, NextHop: nextLabel, Action: "forward",
				Detail: "matched level " + strconv.Itoa(r.Depth) + " (" + dest.format() + ") -> " +
					nextLabel + " @ " + hop + " (CROSS-INTERNET)",
			})
			d.sendTo(hop, dest, consumed, payload)
			return
		}
	}
}

func (d *daemon) sendTo(hop string, dest destination, consumed int, payload []byte) {
	addr, err := net.ResolveUDPAddr("udp", hop)
	if err != nil {
		return
	}
	if b := dest.encode(consumed, payload); b != nil {
		d.conn.WriteToUDP(b, addr)
	}
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
		var body struct {
			Name   string `json:"name"`
			Format string `json:"format"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		// A fake sealed payload (0xD8) — routers never open it.
		payload := append([]byte{0xD8}, []byte("sealed-demo-payload")...)

		// An unrecognised format used to fall through to the fixed address,
		// so a typo — or a caller talking to a daemon too old to know about
		// namespace paths — silently got a 32-byte frame and a success
		// reply. That is defect 7's lesson in a different costume: never
		// report success for something other than what was asked for.
		switch body.Format {
		case "", "fixed", "path":
		default:
			writeJSON(w, map[string]any{
				"error": fmt.Sprintf("unknown format %q: use \"fixed\" or \"path\"", body.Format)})
			return
		}

		if body.Format == "path" {
			p, err := d.ns.Resolve(body.Name)
			if err != nil {
				writeJSON(w, map[string]any{"error": err.Error()})
				return
			}
			enc, _ := p.Encode()
			d.emit(event{Node: d.cfg.Node, Action: "inject",
				Detail: body.Name + " = [" + p.String() + "] via namespace path, " + strconv.Itoa(len(enc)) + " bytes",
				Value:  p.String()})
			d.route(pathDest{path: p}, 0, payload, nil)
			writeJSON(w, map[string]any{
				"injected": body.Name, "format": "namespace-path",
				"path": p.String(), "wire_bytes": len(enc),
			})
			return
		}

		reg := dnxaddr.NewRegistry()
		a, err := reg.FromName(body.Name)
		if err != nil {
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		d.emit(event{Node: d.cfg.Node, Action: "inject",
			Detail: body.Name + " = " + a.String() + " via fixed address, 32 bytes", Value: a.String()})
		d.route(fixedDest{addr: a}, 0, payload, nil)
		writeJSON(w, map[string]any{
			"injected": body.Name, "format": "fixed-address",
			"address": a.String(), "wire_bytes": 32,
		})
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
