package main

// End-to-end tests for following a delegation chain.
//
// The seven existing federation tests all live on the registry side and all
// run at config-load time: they check that a delegation table is well formed
// before it is ever used. That is worth having, but it protects an honest
// operator from a typo — it says nothing about what a RESOLVER accepts off
// the wire, and an attacker does not load his referrals from our JSON file.
//
// Everything below therefore drives resolve() against registries that answer
// however the test wants, including referrals no honest registry would emit.

import (
	"crypto/ed25519"
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"

	"dnx/internal/identity"
	"dnx/internal/proto"
)

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

// fakeRegistry is a UDP endpoint that answers RESOLVE however a test tells it
// to, signed with its own key. It also records any INTRO that lands on it,
// which is how we check that rendezvous went to the right place.
type fakeRegistry struct {
	conn   *net.UDPConn
	priv   ed25519.PrivateKey
	pubB64 string
	addr   *net.UDPAddr
	intros chan string // INTRO targets received here
}

// newFakeRegistry starts a registry stub. answer is called for every RESOLVE
// and returns the reply to send, or nil to stay silent.
func newFakeRegistry(t *testing.T,
	answer func(fr *fakeRegistry, m *proto.Message) *proto.Message) *fakeRegistry {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	fr := &fakeRegistry{
		conn:   conn,
		priv:   priv,
		pubB64: base64.StdEncoding.EncodeToString(pub),
		addr:   conn.LocalAddr().(*net.UDPAddr),
		intros: make(chan string, 8),
	}
	t.Cleanup(func() { conn.Close() })

	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				return // socket closed at test end
			}
			m, err := proto.Decode(buf[:n])
			if err != nil {
				continue
			}
			switch m.Kind {
			case proto.KindIntro:
				select {
				case fr.intros <- m.Target:
				default:
				}
			case proto.KindResolve:
				if reply := answer(fr, m); reply != nil {
					conn.WriteToUDP(proto.Encode(reply), src)
				}
			}
		}
	}()
	return fr
}

// refer builds a REFERRAL delegating zoneName to child, signed by fr.
// signer lets a test sign with the WRONG key to forge one.
func (fr *fakeRegistry) refer(m *proto.Message, zoneName string,
	child *fakeRegistry, signer ed25519.PrivateKey) *proto.Message {
	ts := time.Now().UnixMilli()
	ref := &proto.Message{
		Kind:     proto.KindReferral,
		Target:   m.Target,
		Zone:     zoneName,
		Endpoint: child.addr.String(),
		PubKey:   child.pubB64,
		TS:       ts,
		Nonce:    m.Nonce, // echoing the question binds the answer to it
	}
	ref.Sig = proto.SignDetached(signer,
		proto.ReferralBytes(m.Target, zoneName, ref.Endpoint, child.pubB64, ts, m.Nonce))
	return ref
}

// answerWith builds a signed RESOLVE_RESP binding the target to peerKey.
func (fr *fakeRegistry) answerWith(m *proto.Message, peerKey, endpoint string) *proto.Message {
	ts := time.Now().UnixMilli()
	resp := &proto.Message{
		Kind:     proto.KindResolveResp,
		Target:   m.Target,
		PubKey:   peerKey,
		Endpoint: endpoint,
		TS:       ts,
		Nonce:    m.Nonce,
	}
	resp.Sig = proto.SignDetached(fr.priv,
		proto.ResolveRespBytes(m.Target, peerKey, endpoint, ts, m.Nonce))
	return resp
}

// newTestAgent builds a node whose trust anchor is root: it knows root's
// address and root's signing key, and nothing else.
func newTestAgent(t *testing.T, root *fakeRegistry) *agent {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	a := &agent{
		id: &identity.Identity{
			Name:     "tester.dnxroute.com",
			Registry: root.addr.String(),
			PubB64:   base64.StdEncoding.EncodeToString(pub),
			PrivB64:  base64.StdEncoding.EncodeToString(priv),
		},
		conn:        conn,
		waiters:     map[string]chan *proto.Message{},
		sessions:    map[string]*peerSession{},
		tunnels:     newTunnelTable(),
		tunnelPorts: map[int]bool{},
		regAddr:     root.addr,
		registryKey: root.pubB64,
	}
	go a.readLoop()
	return a
}

// a peer endpoint the tests hand out as the "resolved" location.
const peerEndpoint = "127.0.0.1:59999"

func somePeerKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return base64.StdEncoding.EncodeToString(pub)
}

// ---------------------------------------------------------------------------
// The chain works
// ---------------------------------------------------------------------------

// TestResolveFollowsSignedReferral: root delegates internal.dnxroute.com to a
// child; the child answers. The resolver must end up trusting the child's
// answer even though it never heard of the child before this exchange.
func TestResolveFollowsSignedReferral(t *testing.T) {
	const target = "mac.internal.dnxroute.com"
	peerKey := somePeerKey(t)

	child := newFakeRegistry(t, func(fr *fakeRegistry, m *proto.Message) *proto.Message {
		return fr.answerWith(m, peerKey, peerEndpoint)
	})
	root := newFakeRegistry(t, func(fr *fakeRegistry, m *proto.Message) *proto.Message {
		return fr.refer(m, "internal.dnxroute.com", child, fr.priv)
	})

	a := newTestAgent(t, root)
	r, err := a.resolve(target, 3*time.Second)
	if err != nil {
		t.Fatalf("resolve through a valid referral failed: %v", err)
	}
	if r.PeerKey != peerKey {
		t.Fatalf("wrong peer key: got %.12s… want %.12s…", r.PeerKey, peerKey)
	}
	// The regression: the answering registry must be the CHILD, because
	// everything after this point has to be asked of whoever is actually
	// authoritative — not of the registry we happened to be configured with.
	if r.Registry.String() != child.addr.String() {
		t.Fatalf("resolve reported registry %s, but the child at %s answered",
			r.Registry, child.addr)
	}
}

// TestIntroGoesToTheDelegatedRegistry is the defect this file was written for.
//
// resolve() may end at a child registry, but intro() used to send the
// rendezvous request to the CONFIGURED registry unconditionally. The root has
// delegated that branch away: it holds no endpoint for the name and cannot
// deliver the PUNCH cue, so NAT traversal fails for exactly the names
// federation exists to serve. Two public peers never notice — they do not
// need the punch — which is why this survived a live deployment.
func TestIntroGoesToTheDelegatedRegistry(t *testing.T) {
	const target = "mac.internal.dnxroute.com"
	peerKey := somePeerKey(t)

	child := newFakeRegistry(t, func(fr *fakeRegistry, m *proto.Message) *proto.Message {
		return fr.answerWith(m, peerKey, peerEndpoint)
	})
	root := newFakeRegistry(t, func(fr *fakeRegistry, m *proto.Message) *proto.Message {
		return fr.refer(m, "internal.dnxroute.com", child, fr.priv)
	})

	a := newTestAgent(t, root)
	r, err := a.resolve(target, 3*time.Second)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	a.intro(target, r.Registry)

	select {
	case got := <-child.intros:
		if got != target {
			t.Fatalf("child got INTRO for %q, want %q", got, target)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the authoritative child registry never received the INTRO — " +
			"rendezvous went somewhere that cannot answer it")
	}

	// And the root must not have been asked: it cannot serve this name.
	select {
	case stray := <-root.intros:
		t.Fatalf("root registry received an INTRO for %q it has delegated away", stray)
	default:
	}
}

// ---------------------------------------------------------------------------
// The chain refuses what it should
// ---------------------------------------------------------------------------

// Condition 1: a referral must be signed by the registry we currently trust.
// Without this an on-path attacker forging one UDP packet hands the resolver
// a registry of his choosing — the section 10.1 impersonation hole, one level
// up, and worse: it surrenders a whole branch rather than a single name.
func TestForgedReferralIsRefused(t *testing.T) {
	const target = "mac.internal.dnxroute.com"
	_, attacker, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	child := newFakeRegistry(t, func(fr *fakeRegistry, m *proto.Message) *proto.Message {
		return fr.answerWith(m, somePeerKey(t), peerEndpoint)
	})
	// Signed by a key the resolver has never trusted.
	root := newFakeRegistry(t, func(fr *fakeRegistry, m *proto.Message) *proto.Message {
		return fr.refer(m, "internal.dnxroute.com", child, attacker)
	})

	a := newTestAgent(t, root)
	if _, err := a.resolve(target, 3*time.Second); err == nil {
		t.Fatal("CRITICAL: followed a referral signed by an untrusted key")
	} else if !strings.Contains(err.Error(), "verification") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// Condition 2: the delegated zone must contain the name asked about.
// A referral for some other branch is simply misdirection.
func TestReferralNotCoveringTheTargetIsRefused(t *testing.T) {
	const target = "mac.internal.dnxroute.com"

	child := newFakeRegistry(t, func(fr *fakeRegistry, m *proto.Message) *proto.Message {
		return fr.answerWith(m, somePeerKey(t), peerEndpoint)
	})
	root := newFakeRegistry(t, func(fr *fakeRegistry, m *proto.Message) *proto.Message {
		return fr.refer(m, "elsewhere.dnxroute.com", child, fr.priv)
	})

	a := newTestAgent(t, root)
	if _, err := a.resolve(target, 3*time.Second); err == nil {
		t.Fatal("CRITICAL: followed a referral for a zone not containing the target")
	} else if !strings.Contains(err.Error(), "does not contain") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// Condition 3: each hop must narrow. This is the one that stops a delegated
// registry from climbing: hand out eng.example.com and a widening referral
// would let its holder claim example.com and every sibling under it.
//
// Note the child here is signing correctly with its own key — it was
// legitimately delegated. Authority is exactly what it must not be able to
// enlarge.
func TestReferralThatWidensIsRefused(t *testing.T) {
	const target = "mac.internal.dnxroute.com"

	grandchild := newFakeRegistry(t, func(fr *fakeRegistry, m *proto.Message) *proto.Message {
		return fr.answerWith(m, somePeerKey(t), peerEndpoint)
	})
	// A legitimately-delegated child that tries to grab the level above it.
	child := newFakeRegistry(t, func(fr *fakeRegistry, m *proto.Message) *proto.Message {
		return fr.refer(m, "dnxroute.com", grandchild, fr.priv)
	})
	root := newFakeRegistry(t, func(fr *fakeRegistry, m *proto.Message) *proto.Message {
		return fr.refer(m, "internal.dnxroute.com", child, fr.priv)
	})

	a := newTestAgent(t, root)
	if _, err := a.resolve(target, 3*time.Second); err == nil {
		t.Fatal("CRITICAL: a delegated registry widened its own authority")
	} else if !strings.Contains(err.Error(), "widens") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// A chain that narrows honestly but never terminates must still be bounded,
// or a cooperating set of registries could pin a resolver in a loop that
// looks legitimate at every single hop.
func TestReferralChainIsBounded(t *testing.T) {
	// 10 labels, so there is room to narrow past maxReferrals.
	const target = "h.g.f.e.d.c.b.a.dnxroute.com"
	labels := strings.Split(target, ".")

	var reg *fakeRegistry
	hop := 0
	reg = newFakeRegistry(t, func(fr *fakeRegistry, m *proto.Message) *proto.Message {
		hop++
		// Each reply narrows by one label and points back at this same
		// registry — every hop is individually valid, so only the hop
		// cap can stop it. Zone at hop n is the n+2 label suffix:
		// a.dnxroute.com, then b.a.dnxroute.com, and so on.
		k := hop + 2
		if k > len(labels) {
			return nil
		}
		return fr.refer(m, strings.Join(labels[len(labels)-k:], "."), reg, fr.priv)
	})

	a := newTestAgent(t, reg)
	if _, err := a.resolve(target, 5*time.Second); err == nil {
		t.Fatal("CRITICAL: an unbounded delegation chain was followed to the end")
	} else if !strings.Contains(err.Error(), "too long") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}
