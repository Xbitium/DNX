package nspath

import (
	"fmt"
	"testing"
)

// A router holds one table, keyed by the identifier at the single level it is
// responsible for. Table size is the number of children it must distinguish —
// not the number of hosts anywhere below it.
type router struct {
	name  string
	depth int
	fib   map[uint32]string // identifier at this depth -> next hop
}

const deliver = ":deliver"

// forward walks a path through a topology, reading exactly one level per hop.
func forward(topo map[string]*router, entry string, p Path) (hops []string, delivered bool) {
	cur := topo[entry]
	for i := 0; i < MaxDepth+2; i++ { // loop guard
		if cur == nil {
			return hops, false
		}
		nid, ok := p.At(cur.depth)
		if !ok {
			hops = append(hops, fmt.Sprintf("%s: path has no level %d — dropped", cur.name, cur.depth))
			return hops, false
		}
		next, ok := cur.fib[nid]
		if !ok {
			hops = append(hops, fmt.Sprintf("%s: no route for %d at level %d — dropped", cur.name, nid, cur.depth))
			return hops, false
		}
		hops = append(hops, fmt.Sprintf("%s: matched %d at level %d -> %s", cur.name, nid, cur.depth, next))
		if next == deliver {
			return hops, true
		}
		cur = topo[next]
	}
	return hops, false
}

// TestForwardingAtArbitraryDepth is the claim DNXP-0001 exists to make good
// on. The fixed address could not express a six-level name at all; here one
// is forwarded hop by hop, each router reading a single level.
func TestForwardingAtArbitraryDepth(t *testing.T) {
	tr := NewTree()
	const target = "vpn.engineering.floor3.buildingA.dnxroute.com"
	path, err := tr.Allocate(target)
	if err != nil {
		t.Fatal(err)
	}
	if path.Depth() != 6 {
		t.Fatalf("expected six levels, got %d", path.Depth())
	}

	// Build a router per level, wired from the allocated path.
	topo := map[string]*router{}
	names := []string{"root", "com-gw", "dnxroute-gw", "buildingA", "floor3", "engineering"}
	for i, n := range names {
		next := deliver
		if i+1 < len(names) {
			next = names[i+1]
		}
		topo[n] = &router{name: n, depth: i, fib: map[uint32]string{path[i]: next}}
	}

	hops, ok := forward(topo, "root", path)
	for _, h := range hops {
		t.Log("  ", h)
	}
	if !ok {
		t.Fatal("a six-level name failed to route")
	}
	if len(hops) != 6 {
		t.Fatalf("expected one hop per level, got %d", len(hops))
	}
}

// TestCoreTableDoesNotGrowWithHosts is the aggregation argument, checked
// rather than asserted: adding hosts deep in the tree must not add entries to
// a router near the root.
func TestCoreTableDoesNotGrowWithHosts(t *testing.T) {
	tr := NewTree()
	core := &router{name: "core", depth: 0, fib: map[uint32]string{}}

	// One entry per top-level namespace, installed as they appear.
	install := func(name string) {
		p, err := tr.Allocate(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, known := core.fib[p[0]]; !known {
			core.fib[p[0]] = "tld-gw"
		}
	}

	install("host1.dnx.dnxroute.com")
	afterFirst := len(core.fib)

	// A thousand more hosts under the same top level.
	for i := 0; i < 1000; i++ {
		install(fmt.Sprintf("host%d.dnx.dnxroute.com", i))
	}
	if len(core.fib) != afterFirst {
		t.Fatalf("CRITICAL: the core table grew from %d to %d while adding hosts beneath it",
			afterFirst, len(core.fib))
	}

	// A genuinely new top level does add exactly one entry.
	install("x.dod.gov")
	if len(core.fib) != afterFirst+1 {
		t.Fatalf("a new top-level namespace should add exactly one entry, table is now %d", len(core.fib))
	}
	t.Logf("core table: %d entries after 1001 hosts across 2 top-level namespaces", len(core.fib))
}

// TestUnknownLevelDropsDefinitively: a router owning a level is authoritative
// for its children, so an unknown identifier is a final answer, not a reason
// to send the packet somewhere else and hope. That mistake produced a routing
// loop earlier in this project.
func TestUnknownLevelDropsDefinitively(t *testing.T) {
	tr := NewTree()
	good, _ := tr.Allocate("host1.dnx.dnxroute.com")

	topo := map[string]*router{
		"root": {name: "root", depth: 0, fib: map[uint32]string{good[0]: "gw"}},
		"gw":   {name: "gw", depth: 1, fib: map[uint32]string{good[1]: deliver}},
	}

	stray := Path{good[0], 9999}
	hops, ok := forward(topo, "root", stray)
	if ok {
		t.Fatal("a path with no route should not be delivered")
	}
	if len(hops) != 2 {
		t.Fatalf("expected the drop at the second hop, got %d hops: %v", len(hops), hops)
	}
	t.Log("  ", hops[len(hops)-1])
}
