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
	// retiredFixedMagic marked the fixed four-field address, the original
	// wire format. It is RETIRED: the constant survives only so a frame
	// from an old sender is refused by name instead of shrugged off as
	// noise — version skew is the ordinary condition of a protocol
	// (defect 9), and a refusal that names what it refuses is the only
	// kind an operator can act on.
	retiredFixedMagic = 0xDF
	pathMagic         = 0xDE // variable-length namespace path (DNXP-0001)
)

// ---- variable-length namespace path (DNXP-0001) ----

// pathDest is a frame's destination. Until the fixed address was retired
// this sat behind a two-implementation interface whose docstring argued the
// two formats could share one walk; the migration completed, the argument
// won, and the interface went with the format it existed for.
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

// decode parses a namespace-path frame — the only wire format there is.
func decode(b []byte) (pathDest, int, []byte, error) {
	if len(b) < 1 {
		return pathDest{}, 0, nil, fmt.Errorf("empty frame")
	}
	switch b[0] {
	case retiredFixedMagic:
		// Recognised, and refused for what it is. The sender is running a
		// binary from before the migration completed; that is a fact worth
		// stating precisely, not a parse error.
		return pathDest{}, 0, nil, fmt.Errorf("fixed-address frame (0xDF): that format is retired; this network forwards namespace paths only")

	case pathMagic:
		if len(b) < 2 {
			return pathDest{}, 0, nil, fmt.Errorf("truncated path frame")
		}
		p, err := nspath.Decode(b[1:])
		if err != nil {
			return pathDest{}, 0, nil, fmt.Errorf("path frame: %w", err)
		}
		encLen := nspath.EncodedLen(p.Depth())
		if len(b) < 1+encLen+2 {
			return pathDest{}, 0, nil, fmt.Errorf("truncated path frame")
		}
		return pathDest{path: p}, int(binary.BigEndian.Uint16(b[1+encLen:])), b[1+encLen+2:], nil
	}
	return pathDest{}, 0, nil, fmt.Errorf("unrecognised frame marker 0x%02X", b[0])
}

// ---------------------------------------------------------------------------
// Node configuration
// ---------------------------------------------------------------------------

// routerCfg is one router hosted by this daemon.
type routerCfg struct {
	Name  string `json:"name"`
	Depth int    `json:"depth"` // which level of the destination this router reads

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
	registry := flag.String("registry", "",
		"registry to fetch the namespace-identifier table from (host:port; empty keeps config-order derivation)")
	registryKey := flag.String("registry-key", "",
		"base64 signing key of that registry — an unverified table is a routing plan from whoever answered fastest")
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

	switch {
	case *registry != "":
		// The authority's table, verified and grafted — identifiers are
		// RECEIVED, so configuration order cannot matter. This is the mode
		// that retires the hand-synchronised-namespace hazard (10.3).
		if *registryKey == "" {
			log.Fatalf("--registry needs --registry-key: an unverified namespace table is not a namespace table")
		}
		if err := d.syncNamespace(*registry, *registryKey); err != nil {
			// Startup failure, not a warning: a router that starts with an
			// empty table drops namespace-path traffic while looking
			// healthy, and the config fallback below would derive numbers
			// that may contradict what the authority already published.
			log.Fatalf("namespace: %v", err)
		}
		go d.namespaceRefreshLoop(*registry, *registryKey, 60*time.Second)

	case len(cfg.Namespace) > 0:
		// Legacy: derive from config order. Correct only while every node's
		// config lists the same names in the same order.
		log.Printf("namespace derived from config order — hand-synchronised across nodes (see whitepaper 10.3); prefer --registry")
		for _, n := range cfg.Namespace {
			p, err := d.ns.Allocate(n)
			if err != nil {
				log.Fatalf("namespace %q: %v", n, err)
			}
			log.Printf("  namespace %s -> [%s] (%d bytes on the wire, vs 32 fixed)",
				n, p.String(), nspath.EncodedLen(p.Depth()))
		}
	}
	for i := range cfg.Routers {
		r := &cfg.Routers[i]
		d.routers[r.Depth] = r
	}

	log.Printf("dnx-routerd up: node=%s, hosting %d router(s), listen=%s", cfg.Node, len(cfg.Routers), *listen)
	for _, r := range cfg.Routers {
		log.Printf("  router %q matches %s level (depth %d), %d route(s)", r.Name, levelName(r.Depth), r.Depth, len(r.NIDs))
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
		dest, consumed, payload, err := decode(buf[:n])
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
func (d *daemon) route(dest pathDest, consumed int, payload []byte, src *net.UDPAddr) {
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
				Node: d.cfg.Node, Router: r.Name, Field: levelName(r.Depth),
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
				Node: d.cfg.Node, Router: r.Name, Field: levelName(r.Depth),
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
				Node: d.cfg.Node, Router: r.Name, Field: levelName(r.Depth),
				Value: key, NextHop: nextLabel, Action: "forward",
				Detail: "matched level " + strconv.Itoa(r.Depth) + " (" + dest.format() + ") -> next level on same node",
			})
			continue

		default:
			d.emit(event{
				Node: d.cfg.Node, Router: r.Name, Field: levelName(r.Depth),
				Value: key, NextHop: nextLabel, Action: "forward",
				Detail: "matched level " + strconv.Itoa(r.Depth) + " (" + dest.format() + ") -> " +
					nextLabel + " @ " + hop + " (CROSS-INTERNET)",
			})
			d.sendTo(hop, dest, consumed, payload)
			return
		}
	}
}

func (d *daemon) sendTo(hop string, dest pathDest, consumed int, payload []byte) {
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

		// An unrecognised format used to fall through to the fixed address
		// (defect 9); then the formats were named; now one of them is gone.
		// "fixed" stays recognised so the answer can say what happened to it
		// — a vanished option reads as a typo, a retirement reads as a fact.
		switch body.Format {
		case "", "path":
		case "fixed":
			writeJSON(w, map[string]any{
				"error": "the fixed-address format is retired: the registry allocates namespace identifiers now, and this network forwards paths only"})
			return
		default:
			writeJSON(w, map[string]any{
				"error": fmt.Sprintf("unknown format %q: this network forwards namespace paths (use \"path\" or omit the field)", body.Format)})
			return
		}

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
	}))

	// GET /topology -> this node's routers and links, for the dashboard diagram.
	mux.HandleFunc("/topology", cors(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, d.cfg)
	}))

	log.Printf("telemetry API on %s", listen)
	http.ListenAndServe(listen, mux)
}

// levelName is the human label for a namespace depth. The first four names
// are inherited vocabulary — the retired fixed format had exactly these four
// tiers — and they remain the natural words for what those levels hold.
func levelName(depth int) string {
	switch depth {
	case 0:
		return "TLD"
	case 1:
		return "domain"
	case 2:
		return "subdomain"
	case 3:
		return "host"
	}
	return fmt.Sprintf("level-%d", depth)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
