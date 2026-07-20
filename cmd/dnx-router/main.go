// dnx-router (v2): proof of concept for DNX routing over the 256-bit
// STRUCTURED ADDRESS. This is the hardware-credible version.
//
// The upgrade over v1: routers no longer match text tiers. Each router
// masks the DNX address to ITS 64-bit field and compares integers —
// exactly the fixed-width operation IP silicon does today, just 64-bit
// and semantically structured. Aggregation and blind sealed forwarding
// are unchanged; the forwarding primitive is now hardware-plausible.
//
// Usage: dnx-router   |   dnx-router --json
package main

import (
	"os"
	"time"

	"dnx/internal/dnxaddr"
	"dnx/internal/secure"
)

// fieldTable maps a 64-bit field value to a next hop, for ONE router at one
// tier depth. The DNX FIB, now numeric. Size = distinct children = O(children).
type fieldTable struct {
	depth   int               // which 64-bit field this router matches (0=TLD..3=host)
	entries map[uint64]string // field value -> next hop
}

func newFieldTable(depth int) *fieldTable      { return &fieldTable{depth: depth, entries: map[uint64]string{}} }
func (t *fieldTable) add(v uint64, hop string) { t.entries[v] = hop }
func (t *fieldTable) size() int                { return len(t.entries) }

// router: a name, the tier field it matches, its numeric table, its links.
type router struct {
	name  string
	table *fieldTable
	links map[string]*router
}

func newRouter(name string, depth int) *router {
	return &router{name: name, table: newFieldTable(depth), links: map[string]*router{}}
}
func (r *router) link(fieldVal uint64, hopName string, neighbor *router) {
	r.table.add(fieldVal, hopName)
	if neighbor != nil {
		r.links[hopName] = neighbor
	}
}

const hopLocal = ":local"

// hop is one line of the forwarding trace.
type hop struct {
	Router     string  `json:"router"`
	Depth      int     `json:"field_depth"`
	FieldName  string  `json:"field"`
	FieldValue string  `json:"field_value_hex"`
	NextHop    string  `json:"next_hop"`
	Reason     string  `json:"reason"`
	LookupNs   int64   `json:"lookup_ns"`
	LookupUs   float64 `json:"lookup_us"`
}

type network struct{ entry *router }

// forward: hop-by-hop 64-bit field matching. The frame stays sealed.
func (n *network) forward(a dnxaddr.Addr, sealed []byte) ([]hop, bool) {
	var trace []hop
	cur := n.entry
	const maxHops = 8

	for i := 0; i < maxHops; i++ {
		depth := cur.table.depth
		field := a.FieldAt(depth) // THE ONLY READ: mask to this router's 64 bits

		t0 := time.Now()
		hopName, ok := cur.table.entries[field] // one integer map lookup
		dt := time.Since(t0)

		h := hop{
			Router:     cur.name,
			Depth:      depth,
			FieldName:  dnxaddr.FieldName(depth),
			FieldValue: hex64(field),
			LookupNs:   dt.Nanoseconds(),
			LookupUs:   float64(dt.Nanoseconds()) / 1000.0,
		}

		if !ok {
			h.NextHop = "DROP"
			h.Reason = cur.name + " matches " + dnxaddr.FieldName(depth) +
				" field; value " + hex64(field) + " not allocated here; dropped"
			trace = append(trace, h)
			return trace, false
		}
		if hopName == hopLocal {
			h.NextHop = "DELIVER"
			h.Reason = "host field matched locally; deliver"
			trace = append(trace, h)
			return trace, true
		}
		h.NextHop = hopName
		h.Reason = "matched " + dnxaddr.FieldName(depth) + " field " + hex64(field) +
			" -> " + hopName + " (did not read lower fields)"
		trace = append(trace, h)

		nxt, ok := cur.links[hopName]
		if !ok {
			trace[len(trace)-1].NextHop = "DROP"
			trace[len(trace)-1].Reason = "dangling link (misconfig)"
			return trace, false
		}
		cur = nxt
	}
	return trace, false
}

func main() {
	jsonOut := len(os.Args) > 1 && os.Args[1] == "--json"
	reg := dnxaddr.NewRegistry()

	dst, err := reg.FromName("host1.dnx.dnxroute.com")
	if err != nil {
		panic(err)
	}

	core := newRouter("core", dnxaddr.TLD)
	domRtr := newRouter("dnxroute-gw", dnxaddr.Domain)
	subRtr := newRouter("dnx-rtr", dnxaddr.Subdomain)
	hostRtr := newRouter("leaf-sw", dnxaddr.Host)

	// Core: one entry per TLD block — matches ONLY the top 64 bits.
	core.link(dst.Field[dnxaddr.TLD], "dnxroute-gw", domRtr)
	govAddr, _ := reg.FromName("x.dod.gov")
	core.link(govAddr.Field[dnxaddr.TLD], "gov-core", nil) // 2nd TLD, proves one-per-TLD table

	domRtr.link(dst.Field[dnxaddr.Domain], "dnx-rtr", subRtr)
	subRtr.link(dst.Field[dnxaddr.Subdomain], "leaf-sw", hostRtr)
	hostRtr.link(dst.Field[dnxaddr.Host], hopLocal, nil)

	net := &network{entry: core}
	sealed := buildSealedFrame()

	trace1, ok1 := net.forward(dst, sealed)

	badAddr := dnxaddr.Addr{}
	badAddr.Field[dnxaddr.TLD] = 0xDEADBEEF00000000 // never allocated
	traceBad, okBad := net.forward(badAddr, sealed)

	if jsonOut {
		emitJSON(dst, trace1, ok1, traceBad, okBad, core, reg, sealed)
		return
	}
	printHuman(dst, trace1, ok1, traceBad, okBad, core, reg, sealed)
}

func buildSealedFrame() []byte {
	ephA, _ := secure.NewEphemeral()
	ephB, _ := secure.NewEphemeral()
	nA, nB := secure.NewNonce(), secure.NewNonce()
	aSess, _ := secure.Derive(ephA, ephB.Pub, "host1.dnx.dnxroute.com", "k", nA, nB, true)
	return aSess.Seal([]byte(`{"k":"PING","msg":"routed by 256-bit name address"}`))
}

func hex64(v uint64) string {
	const hexd = "0123456789abcdef"
	var b [16]byte
	for i := 15; i >= 0; i-- {
		b[i] = hexd[v&0xF]
		v >>= 4
	}
	return "0x" + string(b[:])
}
