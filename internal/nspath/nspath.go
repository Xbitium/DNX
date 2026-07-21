// Package nspath implements DNXP-0001: variable-length namespace paths.
//
// It replaces the fixed four-field address, which capped hierarchy at four
// levels and broke on the first realistic organisation chart —
// api.production.us-east.customer.company is five.
//
// A destination is an ordered sequence of numeric identifiers, most
// significant first, resolved from a name by the registry. No text rides the
// wire.
//
//	host1.dnx.dnxroute.com   ->   [ com=1, dnxroute=1, dnx=1, host1=1 ]
//	                              wire: [count=4][1][1][1][1]  = 17 bytes
//
// # PARENT-SCOPED IDENTIFIERS
//
// An identifier is unique only among its siblings, not globally. That is safe
// because forwarding is inherently top-down: a router responsible for level k
// only ever sees packets whose levels 0..k-1 have already matched, so the
// parent context is guaranteed by the time the identifier is read. It is also
// what keeps identifiers small and dense, and — the part that matters for
// governance — it means each namespace allocates its own without asking a
// central authority for anything.
//
// The cost is that an identifier means nothing on its own. That is fine for
// hierarchical forwarding, which never needs to match a deep level in
// isolation, but it does make a misrouted packet hard to read, which is why
// this package also provides reverse resolution (see Tree.Reverse).
package nspath

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
)

const (
	// MaxDepth bounds the worst-case work a router can be asked to do. The
	// count field could express 255 levels; nothing legitimate comes close,
	// and an unbounded walk is an invitation.
	MaxDepth = 16

	// NIDSize is the width of one identifier on the wire.
	NIDSize = 4
)

var (
	ErrTooDeep      = errors.New("namespace path exceeds the maximum depth")
	ErrEmpty        = errors.New("namespace path is empty")
	ErrMalformed    = errors.New("malformed namespace path")
	ErrNotAllocated = errors.New("name has no allocated path")
	ErrExhausted    = errors.New("identifier space exhausted under this parent")
)

// Path is an ordered sequence of parent-scoped identifiers, root-most first.
type Path []uint32

// Encode renders a path for transmission: one length byte, then one 32-bit
// identifier per level.
//
//	+---------+--------+--------+     +----------+
//	| count   | NID[0] | NID[1] | ... | NID[n-1] |
//	| 1 byte  | 4 bytes| 4 bytes|     | 4 bytes  |
//	+---------+--------+--------+     +----------+
func (p Path) Encode() ([]byte, error) {
	if len(p) == 0 {
		return nil, ErrEmpty
	}
	if len(p) > MaxDepth {
		return nil, ErrTooDeep
	}
	b := make([]byte, 1+len(p)*NIDSize)
	b[0] = byte(len(p))
	for i, nid := range p {
		binary.BigEndian.PutUint32(b[1+i*NIDSize:], nid)
	}
	return b, nil
}

// Decode parses a wire path. It is strict: a truncated or over-deep path is
// refused rather than silently interpreted, because a misread path routes a
// packet somewhere nobody intended.
func Decode(b []byte) (Path, error) {
	if len(b) < 1 {
		return nil, ErrMalformed
	}
	n := int(b[0])
	if n == 0 {
		return nil, ErrEmpty
	}
	if n > MaxDepth {
		return nil, ErrTooDeep
	}
	if len(b) < 1+n*NIDSize {
		return nil, fmt.Errorf("%w: declares %d levels but carries %d bytes", ErrMalformed, n, len(b)-1)
	}
	p := make(Path, n)
	for i := 0; i < n; i++ {
		p[i] = binary.BigEndian.Uint32(b[1+i*NIDSize:])
	}
	return p, nil
}

// EncodedLen is the wire size of a path of the given depth.
func EncodedLen(depth int) int { return 1 + depth*NIDSize }

// At returns the identifier a router at the given depth matches on, and
// whether that depth exists in this path.
func (p Path) At(depth int) (uint32, bool) {
	if depth < 0 || depth >= len(p) {
		return 0, false
	}
	return p[depth], true
}

func (p Path) Depth() int { return len(p) }

func (p Path) String() string {
	parts := make([]string, len(p))
	for i, n := range p {
		parts[i] = fmt.Sprint(n)
	}
	return strings.Join(parts, ".")
}

// Equal reports whether two paths are identical.
func (p Path) Equal(q Path) bool {
	if len(p) != len(q) {
		return false
	}
	for i := range p {
		if p[i] != q[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Allocation
// ---------------------------------------------------------------------------

type node struct {
	label    string
	nid      uint32
	children map[string]*node
	byNID    map[uint32]*node

	// nextNID allocates monotonically and never reuses.
	//
	// Reuse is the obvious way to keep identifiers dense, and it is a trap:
	// a packet in flight, or a stale forwarding entry, would be delivered to
	// whatever inherited the number. Generation counters would work, but
	// monotonic allocation is simpler and costs nothing — four billion
	// allocations under a single parent is not a limit anyone will reach.
	nextNID uint32
}

func newNode(label string, nid uint32) *node {
	return &node{
		label:    label,
		nid:      nid,
		children: map[string]*node{},
		byNID:    map[uint32]*node{},
		nextNID:  1, // 0 is reserved so an unset identifier is never valid
	}
}

// Tree allocates parent-scoped identifiers and translates between names and
// paths. Safe for concurrent use.
type Tree struct {
	mu   sync.Mutex
	root *node
}

func NewTree() *Tree { return &Tree{root: newNode("", 0)} }

// splitName turns a FQDN into labels ordered root-most first, which is the
// opposite of how a name is written.
func splitName(fqdn string) []string {
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(strings.ToLower(fqdn)), ".") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	// reverse: host1.dnx.dnxroute.com -> com, dnxroute, dnx, host1
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// Allocate assigns identifiers to any level of the name that does not have
// one yet, and returns the full path. Existing levels keep their identifiers,
// so allocating a sibling never disturbs one already in use.
func (t *Tree) Allocate(fqdn string) (Path, error) {
	labels := splitName(fqdn)
	if len(labels) == 0 {
		return nil, ErrEmpty
	}
	if len(labels) > MaxDepth {
		return nil, fmt.Errorf("%w: %q has %d levels, limit is %d", ErrTooDeep, fqdn, len(labels), MaxDepth)
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	cur := t.root
	path := make(Path, 0, len(labels))
	for _, label := range labels {
		child, ok := cur.children[label]
		if !ok {
			if cur.nextNID == 0 {
				return nil, fmt.Errorf("%w: %q", ErrExhausted, label)
			}
			child = newNode(label, cur.nextNID)
			cur.children[label] = child
			cur.byNID[child.nid] = child
			cur.nextNID++ // monotonic: never reused, even after a delete
		}
		path = append(path, child.nid)
		cur = child
	}
	return path, nil
}

// Resolve returns the path for a name that has already been allocated.
func (t *Tree) Resolve(fqdn string) (Path, error) {
	labels := splitName(fqdn)
	if len(labels) == 0 {
		return nil, ErrEmpty
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	cur := t.root
	path := make(Path, 0, len(labels))
	for _, label := range labels {
		child, ok := cur.children[label]
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrNotAllocated, fqdn)
		}
		path = append(path, child.nid)
		cur = child
	}
	return path, nil
}

// Reverse translates a path back into a name.
//
// This exists because the wire carries only opaque numbers. Without it a
// packet delivered to the wrong place cannot be explained, which would make
// the network undebuggable in exactly the situation where debugging matters.
func (t *Tree) Reverse(p Path) (string, error) {
	if len(p) == 0 {
		return "", ErrEmpty
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	cur := t.root
	labels := make([]string, 0, len(p))
	for depth, nid := range p {
		child, ok := cur.byNID[nid]
		if !ok {
			return "", fmt.Errorf("%w: no identifier %d at depth %d", ErrNotAllocated, nid, depth)
		}
		labels = append(labels, child.label)
		cur = child
	}
	// back to written order
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return strings.Join(labels, "."), nil
}

// Forget removes a name's leaf so it stops resolving. The identifier is NOT
// returned to the pool: see node.nextNID.
func (t *Tree) Forget(fqdn string) error {
	labels := splitName(fqdn)
	if len(labels) == 0 {
		return ErrEmpty
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	cur := t.root
	for _, label := range labels[:len(labels)-1] {
		child, ok := cur.children[label]
		if !ok {
			return fmt.Errorf("%w: %q", ErrNotAllocated, fqdn)
		}
		cur = child
	}
	leaf := labels[len(labels)-1]
	child, ok := cur.children[leaf]
	if !ok {
		return fmt.Errorf("%w: %q", ErrNotAllocated, fqdn)
	}
	delete(cur.children, leaf)
	delete(cur.byNID, child.nid)
	return nil
}
