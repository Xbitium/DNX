package nspath

// Persistence, grafting and enumeration — what a Tree needs to be owned by a
// REGISTRY rather than rebuilt from configuration order.
//
// Order-dependence is the original sin of this allocator: identifiers depend
// on the order names are first seen, so any consumer that re-derives them
// must replay exactly the same history. Three additions remove that burden:
//
//   - Graft inserts a name with identifiers CHOSEN BY THE CALLER, so a
//     consumer can reproduce someone else's allocations exactly, in any
//     order, instead of hoping to re-derive them.
//   - Walk enumerates every allocation, so an authority can publish its
//     table.
//   - Snapshot/Restore persist the tree INCLUDING its counters, so
//     never-reuse survives a restart. Persisting only the live paths would
//     quietly re-issue the identifier of anything released before the
//     snapshot — to whatever registers next. That is name hijack (defect 3)
//     wearing numbers instead of letters.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ErrConflict means a Graft asked for an identifier assignment that
// contradicts one already made. There is no safe way to proceed: one of the
// two assignments is wrong, and the tree cannot know which.
var ErrConflict = fmt.Errorf("namespace identifier conflict")

// Graft inserts fqdn with the exact identifiers given, one per level,
// root-most first. Levels that already exist must MATCH — same label, same
// identifier — and levels that are new are created with the identifier
// demanded rather than the next free one. The per-parent counter is advanced
// past every grafted identifier so later Allocate calls can never collide
// with a grafted subtree.
//
// This is how paths move between machines: the authority Allocates, everyone
// else Grafts what the authority published.
func (t *Tree) Graft(fqdn string, p Path) error {
	labels := splitName(fqdn)
	if len(labels) == 0 {
		return ErrEmpty
	}
	if len(labels) != len(p) {
		return fmt.Errorf("%w: %q has %d levels but the path has %d",
			ErrMalformed, fqdn, len(labels), len(p))
	}
	if len(labels) > MaxDepth {
		return fmt.Errorf("%w: %q has %d levels, limit is %d", ErrTooDeep, fqdn, len(labels), MaxDepth)
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	cur := t.root
	for i, label := range labels {
		nid := p[i]
		if nid == 0 {
			return fmt.Errorf("%w: level %d of %q is zero, which is reserved",
				ErrMalformed, i, fqdn)
		}
		child, ok := cur.children[label]
		if ok {
			// The label exists — its number is settled and must agree.
			if child.nid != nid {
				return fmt.Errorf("%w: %q at level %d is already %d, refusing to renumber it to %d",
					ErrConflict, label, i, child.nid, nid)
			}
		} else {
			// The label is new — but the NUMBER might not be. If some other
			// sibling already holds it, accepting the graft would give one
			// identifier two meanings, and a router would forward packets
			// for both to whichever it learned first.
			if other, taken := cur.byNID[nid]; taken {
				return fmt.Errorf("%w: identifier %d under %q already names %q, cannot also name %q",
					ErrConflict, nid, cur.label, other.label, label)
			}
			child = newNode(label, nid)
			cur.children[label] = child
			cur.byNID[nid] = child
			// Advance the counter past the graft. Without this, a later
			// Allocate under the same parent would hand out an identifier
			// the graft already spoke for.
			if nid >= cur.nextNID {
				cur.nextNID = nid + 1
			}
		}
		cur = child
	}
	return nil
}

// Entry is one allocated name as an authority publishes it.
type Entry struct {
	Name string `json:"name"` // FQDN, written order
	Path Path   `json:"path"` // identifiers, root-most first
}

// Walk returns every allocated name with its path, sorted by name so the
// output is canonical — two trees with the same allocations produce the same
// listing, which is what makes the listing signable.
func (t *Tree) Walk() []Entry {
	t.mu.Lock()
	defer t.mu.Unlock()

	var out []Entry
	var descend func(n *node, labels []string, path Path)
	descend = func(n *node, labels []string, path Path) {
		if n.label != "" { // skip the synthetic root
			labels = append(labels, n.label)
			path = append(path, n.nid)
			// A name is every chain from the root, not only the leaves: the
			// zone "dnx.dnxroute.com" is itself addressable even though
			// hosts exist beneath it.
			name := make([]string, len(labels))
			for i, l := range labels {
				name[len(labels)-1-i] = l // back to written order
			}
			out = append(out, Entry{Name: strings.Join(name, "."), Path: append(Path{}, path...)})
		}
		for _, c := range n.children {
			descend(c, labels, path)
		}
	}
	descend(t.root, nil, nil)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ---------------------------------------------------------------------------
// Snapshot / Restore
// ---------------------------------------------------------------------------

// snapNode is the persisted form of one tree node. Children are keyed by
// label, and the counter travels with the node — the counter IS the memory
// of every identifier ever issued here, including ones whose names are gone.
type snapNode struct {
	NID      uint32               `json:"nid"`
	Next     uint32               `json:"next"`
	Children map[string]*snapNode `json:"children,omitempty"`
}

// Snapshot serialises the whole tree, counters included, as JSON.
func (t *Tree) Snapshot() ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	var pack func(n *node) *snapNode
	pack = func(n *node) *snapNode {
		s := &snapNode{NID: n.nid, Next: n.nextNID}
		if len(n.children) > 0 {
			s.Children = make(map[string]*snapNode, len(n.children))
			for label, c := range n.children {
				s.Children[label] = pack(c)
			}
		}
		return s
	}
	return json.MarshalIndent(pack(t.root), "", "  ")
}

// Restore rebuilds a tree from a Snapshot. It is strict about internal
// consistency, because a corrupted allocation table misroutes everything
// that trusts it: better to refuse the file than to serve it.
func Restore(b []byte) (*Tree, error) {
	var root snapNode
	if err := json.Unmarshal(b, &root); err != nil {
		return nil, fmt.Errorf("namespace snapshot: %w", err)
	}

	var unpack func(label string, s *snapNode, depth int) (*node, error)
	unpack = func(label string, s *snapNode, depth int) (*node, error) {
		if depth > MaxDepth {
			return nil, fmt.Errorf("namespace snapshot: %w", ErrTooDeep)
		}
		n := newNode(label, s.NID)
		if s.Next > 0 {
			n.nextNID = s.Next
		}
		for childLabel, cs := range s.Children {
			c, err := unpack(childLabel, cs, depth+1)
			if err != nil {
				return nil, err
			}
			if c.nid == 0 {
				return nil, fmt.Errorf("namespace snapshot: %q has the reserved identifier 0", childLabel)
			}
			if _, dup := n.byNID[c.nid]; dup {
				return nil, fmt.Errorf("namespace snapshot: identifier %d appears twice under %q", c.nid, label)
			}
			// The counter must be beyond every child, or a restore followed
			// by an Allocate would re-issue a live identifier.
			if c.nid >= n.nextNID {
				return nil, fmt.Errorf("namespace snapshot: %q holds %d but the counter under %q is only %d — this table would reuse identifiers",
					childLabel, c.nid, label, n.nextNID)
			}
			n.children[childLabel] = c
			n.byNID[c.nid] = c
		}
		return n, nil
	}

	rootNode, err := unpack("", &root, 0)
	if err != nil {
		return nil, err
	}
	return &Tree{root: rootNode}, nil
}
