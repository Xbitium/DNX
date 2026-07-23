package main

// End-to-end tests for namespace-identifier publication, from the CONSUMER's
// side of the wire: a registry allocating with the real allocator, answers
// carrying signed paths, a router-style table fetch — and what must be
// refused.
//
// These exist for the same reason the federation e2e tests exist (defect 8):
// the registry-side tests prove the authority allocates correctly, but the
// hazard being retired lives at the CONSUMERS — a router or node trusting
// numbers nobody signed. So the wire is where the proof has to be.

import (
	"crypto/ed25519"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"dnx/internal/nspath"
	"dnx/internal/proto"
	"dnx/internal/secure"
)

// nidAnswer builds RESOLVE and NAMESPACE answers backed by a REAL
// nspath.Tree — the same allocator the registry runs — signed by fr, with a
// tamper hook so tests can serve dishonest variations of honest state.
func nidAnswer(tree *nspath.Tree, peerKey string, tamper func(*proto.Message)) func(*fakeRegistry, *proto.Message) *proto.Message {
	return func(fr *fakeRegistry, m *proto.Message) *proto.Message {
		ts := time.Now().UnixMilli()
		var resp *proto.Message
		switch m.Kind {
		case proto.KindResolve:
			p, _ := tree.Allocate(m.Target) // idempotent for an existing name
			resp = fr.answerWith(m, peerKey, peerEndpoint)
			resp.NsPath = p.String()
			resp.PathSig = proto.SignDetached(fr.priv,
				proto.NsPathBytes(m.Target, resp.NsPath, resp.TS, m.Nonce))
		case proto.KindNamespace:
			table, _ := json.Marshal(tree.Walk())
			resp = &proto.Message{
				Kind: proto.KindNamespaceResp, Zone: "dnxroute.com",
				Info: string(table), TS: ts, Nonce: m.Nonce,
			}
			resp.Sig = proto.SignDetached(fr.priv,
				proto.NamespaceBytes(resp.Zone, resp.Info, ts, m.Nonce))
		default:
			return nil
		}
		if tamper != nil {
			tamper(resp)
		}
		return resp
	}
}

// fetchTable performs the router's fetch on a dedicated socket — the same
// shape as cmd/dnx-routerd's real implementation (which cannot be imported
// across main packages).
func fetchTable(t *testing.T, registry *net.UDPAddr) *proto.Message {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, registry)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	nonce := secure.NewNonce()
	conn.Write(proto.Encode(&proto.Message{
		Kind: proto.KindNamespace, TS: time.Now().UnixMilli(), Nonce: nonce}))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64*1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no table within 3s: %v", err)
	}
	m, err := proto.Decode(buf[:n])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if m.Nonce != nonce {
		t.Fatalf("table answer does not echo the question's nonce")
	}
	return m
}

// ---------------------------------------------------------------------------
// The honest cases
// ---------------------------------------------------------------------------

// A resolve against a path-allocating registry returns the peer's number,
// verified — the consumer needs no allocation machinery of its own.
func TestResolveCarriesTheAllocatedPath(t *testing.T) {
	tree := nspath.NewTree()
	peerKey := somePeerKey(t)
	reg := newFakeRegistry(t, nidAnswer(tree, peerKey, nil))

	a := newTestAgent(t, reg)
	r, err := a.resolve("host1.dnx.dnxroute.com", 3*time.Second)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.NsPath != "1.1.1.1" {
		t.Fatalf("expected the first allocation [1.1.1.1], got %q", r.NsPath)
	}
	// A second name gets the next sibling number, from the same authority.
	r2, err := a.resolve("host2.dnx.dnxroute.com", 3*time.Second)
	if err != nil {
		t.Fatalf("resolve 2: %v", err)
	}
	if r2.NsPath != "1.1.1.2" {
		t.Fatalf("expected [1.1.1.2] for the sibling, got %q", r2.NsPath)
	}
}

// A registry that predates allocation sends no path, and the answer is still
// good — the field is additive, never a requirement. This is the version-skew
// direction defect 9 is about: mixed deployments are the ordinary condition.
func TestResolveWithoutAPathStillWorks(t *testing.T) {
	peerKey := somePeerKey(t)
	reg := newFakeRegistry(t, func(fr *fakeRegistry, m *proto.Message) *proto.Message {
		if m.Kind != proto.KindResolve {
			return nil
		}
		return fr.answerWith(m, peerKey, peerEndpoint) // no NsPath at all
	})
	a := newTestAgent(t, reg)
	r, err := a.resolve("host1.dnx.dnxroute.com", 3*time.Second)
	if err != nil {
		t.Fatalf("a pathless answer must remain acceptable: %v", err)
	}
	if r.NsPath != "" {
		t.Fatalf("invented a path from nowhere: %q", r.NsPath)
	}
}

// The router-style table fetch: signed, canonical, verifiable.
func TestNamespaceTableFetchVerifies(t *testing.T) {
	tree := nspath.NewTree()
	for _, n := range []string{"host1.dnx.dnxroute.com", "host2.dnx.dnxroute.com"} {
		if _, err := tree.Allocate(n); err != nil {
			t.Fatal(err)
		}
	}
	reg := newFakeRegistry(t, nidAnswer(tree, somePeerKey(t), nil))

	m := fetchTable(t, reg.addr)
	if err := proto.VerifyDetached(reg.pubB64,
		proto.NamespaceBytes(m.Zone, m.Info, m.TS, m.Nonce), m.Sig); err != nil {
		t.Fatalf("honest table failed verification: %v", err)
	}
	// And grafting it — any order — reproduces the authority's numbering.
	var entries []nspath.Entry
	if err := json.Unmarshal([]byte(m.Info), &entries); err != nil {
		t.Fatalf("table json: %v", err)
	}
	mine := nspath.NewTree()
	for i := len(entries) - 1; i >= 0; i-- {
		if err := mine.Graft(entries[i].Name, entries[i].Path); err != nil {
			t.Fatalf("graft %s: %v", entries[i].Name, err)
		}
	}
	want, _ := tree.Resolve("host2.dnx.dnxroute.com")
	got, err := mine.Resolve("host2.dnx.dnxroute.com")
	if err != nil || !got.Equal(want) {
		t.Fatalf("grafted table disagrees with the authority: got %v want %v (err %v)", got, want, err)
	}
}

// ---------------------------------------------------------------------------
// What must be refused
// ---------------------------------------------------------------------------

// A path signed by nobody we trust is a routing instruction from an
// attacker, and the WHOLE answer dies with it — accepting the answer while
// dropping the path would be a silent downgrade (defect 9's shape), and
// worse: it would train on-path attackers that corrupting the path field
// quietly strips a capability instead of raising an alarm.
func TestTamperedPathKillsTheWholeAnswer(t *testing.T) {
	tree := nspath.NewTree()
	_, attacker, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]func(*proto.Message){
		"renumbered path": func(m *proto.Message) {
			if m.Kind == proto.KindResolveResp {
				m.NsPath = "1.1.1.99" // signature no longer covers this
			}
		},
		"attacker-signed path": func(m *proto.Message) {
			if m.Kind == proto.KindResolveResp {
				m.PathSig = proto.SignDetached(attacker,
					proto.NsPathBytes(m.Target, m.NsPath, m.TS, m.Nonce))
			}
		},
		"missing path signature": func(m *proto.Message) {
			if m.Kind == proto.KindResolveResp {
				m.PathSig = ""
			}
		},
	}
	for label, tamper := range cases {
		reg := newFakeRegistry(t, nidAnswer(tree, somePeerKey(t), tamper))
		a := newTestAgent(t, reg)
		_, err := a.resolve("host1.dnx.dnxroute.com", 3*time.Second)
		if err == nil {
			t.Fatalf("CRITICAL: an answer with a %s was accepted", label)
		}
		if !strings.Contains(err.Error(), "namespace path") {
			t.Fatalf("%s: refused for the wrong reason: %v", label, err)
		}
	}
}

// A tampered table must fail the router's verification — a namespace table
// nobody signed is a routing plan from whoever answered fastest.
func TestTamperedNamespaceTableIsDetected(t *testing.T) {
	tree := nspath.NewTree()
	if _, err := tree.Allocate("host1.dnx.dnxroute.com"); err != nil {
		t.Fatal(err)
	}
	reg := newFakeRegistry(t, nidAnswer(tree, somePeerKey(t), func(m *proto.Message) {
		if m.Kind == proto.KindNamespaceResp {
			// Renumber one entry after signing — an on-path rewrite.
			m.Info = strings.Replace(m.Info, `[1,1,1,1]`, `[1,1,1,9]`, 1)
		}
	}))
	m := fetchTable(t, reg.addr)
	if err := proto.VerifyDetached(reg.pubB64,
		proto.NamespaceBytes(m.Zone, m.Info, m.TS, m.Nonce), m.Sig); err == nil {
		t.Fatal("CRITICAL: a renumbered namespace table verified")
	}
}
