// output.go — rendering the 256-bit address forwarding trace.
package main

import (
	"encoding/json"
	"fmt"

	"dnx/internal/dnxaddr"
)

func printHuman(dst dnxaddr.Addr, trace1 []hop, ok1 bool, traceBad []hop, okBad bool, core *router, reg *dnxaddr.Registry, sealed []byte) {
	line := "══════════════════════════════════════════════════════════════════════"
	fmt.Println(line)
	fmt.Println("  DNX ROUTER v2 — forwarding by 256-bit STRUCTURED NAME ADDRESS")
	fmt.Println(line)

	fmt.Println()
	fmt.Println("NAME -> 256-BIT ADDRESS (hybrid: TLD/domain assigned, sub/host hashed):")
	fmt.Println("  host1.dnx.dnxroute.com")
	fmt.Printf("  = %s\n", dst.String())
	fmt.Printf("    %s\n", dst.Pretty())
	fmt.Println("    └ TLD & domain: registry-assigned (aggregatable)")
	fmt.Println("    └ subdomain & host: hash(label) truncated to 64 bits (self-service)")

	fmt.Println()
	fmt.Printf("SEALED FRAME carried blindly: magic=0x%02X, %d bytes ciphertext.\n", sealed[0], len(sealed))

	fmt.Println()
	fmt.Println(line)
	fmt.Println("  DEMO 1 — multi-hop forwarding by 64-bit field match")
	fmt.Println(line)
	fmt.Println("  hop  router        matches field  value                lookup")
	fmt.Println("  ───  ────────────  ─────────────  ──────────────────   ───────")
	for i, h := range trace1 {
		fmt.Printf("  %2d   %-12s  %-13s  %s   %.3f µs\n", i+1, h.Router, h.FieldName, h.FieldValue, h.LookupUs)
	}
	fmt.Println()
	for _, h := range trace1 {
		fmt.Printf("    · %s\n", h.Reason)
	}
	fmt.Println()
	if ok1 {
		fmt.Println("  RESULT: delivered. Each hop masked to ONE 64-bit field — a fixed-width")
		fmt.Println("  integer compare, the same operation IP hardware already does at line rate.")
	}

	fmt.Println()
	fmt.Println(line)
	fmt.Println("  DEMO 2 — aggregation: the core's entire table")
	fmt.Println(line)
	fmt.Println("core router matches the TLD field (top 64 bits only):")
	for v, hop := range core.table.entries {
		fmt.Printf("    %s -> %s\n", hex64(v), hop)
	}
	fmt.Printf("\n  core table size: %d entries — ONE per TLD block.\n", core.table.size())
	fmt.Println("  Every host under .com — millions — shares the SAME top-64-bit route.")
	fmt.Println("  The core never sees domain, subdomain, or host bits. O(TLDs), not O(hosts).")

	fmt.Println()
	fmt.Println(line)
	fmt.Println("  DEMO 3 — unallocated TLD field -> definitive drop at core")
	fmt.Println(line)
	fmt.Println("  destination TLD field: 0xdeadbeef00000000 (never allocated)")
	fmt.Println()
	for i, h := range traceBad {
		fmt.Printf("  %2d   %-12s  matches %-10s %s -> %s\n", i+1, h.Router, h.FieldName, h.FieldValue, h.NextHop)
	}
	fmt.Println()
	if !okBad {
		fmt.Println("  RESULT: dropped at the core. The TLD authority found no such block;")
		fmt.Println("  no router closer to root knows better. One hop, clean, no loop.")
	}

	fmt.Println()
	fmt.Println(line)
	fmt.Println("  256-bit structured addressing: name-meaningful routing, silicon-friendly.")
	fmt.Println(line)
}

func emitJSON(dst dnxaddr.Addr, trace1 []hop, ok1 bool, traceBad []hop, okBad bool, core *router, reg *dnxaddr.Registry, sealed []byte) {
	tbl := map[string]string{}
	for v, hop := range core.table.entries {
		tbl[hex64(v)] = hop
	}
	out := map[string]any{
		"address_model": map[string]any{
			"name":            "host1.dnx.dnxroute.com",
			"address_256":     dst.String(),
			"tld_field":       hex64(dst.Field[dnxaddr.TLD]) + " (registry-assigned)",
			"domain_field":    hex64(dst.Field[dnxaddr.Domain]) + " (registry-assigned)",
			"subdomain_field": hex64(dst.Field[dnxaddr.Subdomain]) + " (hash-derived)",
			"host_field":      hex64(dst.Field[dnxaddr.Host]) + " (hash-derived)",
		},
		"sealed_frame":   map[string]any{"magic": fmt.Sprintf("0x%02X", sealed[0]), "bytes": len(sealed), "routers_decrypted": false},
		"demo1_multihop": map[string]any{"delivered": ok1, "hops": trace1},
		"demo2_aggregation": map[string]any{
			"core_matches": "TLD field (top 64 bits)",
			"core_table":   tbl,
			"core_size":    core.table.size(),
			"note":         "O(TLDs) not O(hosts)",
		},
		"demo3_drop": map[string]any{"delivered": okBad, "hops": traceBad},
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
}
