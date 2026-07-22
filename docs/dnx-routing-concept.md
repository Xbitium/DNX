# DNX: Name-Hierarchical Routing

### A Concept Specification and the Spine of the DNX Whitepaper

**Working draft — v0.3 concept · July 2026 · dnxroute.com**

> **Superseded.** This document described the routing model as it stood before
> federation, signed registry answers, the stream layer and DNXP-0001 existed.
> It is kept for the record; the current description of the protocol is
> [`dnx-whitepaper.md`](dnx-whitepaper.md).

---

## Abstract

DNX (Domain Native eXchange) is an experimental network protocol in which
*names, not numbers, are the unit of both addressing and routing*. Where the
Internet Protocol forwards packets by longest-prefix match over fixed-width
numeric addresses, DNX forwards by **longest-suffix match over an ordered name
hierarchy** — a routing *locator* whose tiers (`root → region → authority →
site → host`) aggregate exactly as IP prefixes do, but along a hierarchy that
is human-designed rather than historically accreted.

The central claim is not that IP addresses can be abolished — beneath DNX they
still move bits — but that the *aggregation key* can be replaced. Numeric
prefixes give routers geography by accident of allocation; a designed name
hierarchy gives routers geography by construction. This document specifies the
DNX addressing and routing model, the forwarding algorithm, the aggregation
analysis that makes it tractable at scale, and an honest account of the
objections it must answer. It defines what the accompanying proof-of-concept
router must demonstrate, and forms the technical spine of the full DNX
whitepaper.

DNX today runs as an authenticated, encrypted overlay on UDP/IP, with a live
registry, cryptographic name→key identity, NAT traversal, and a
ChaCha20-Poly1305 session layer already implemented and deployed. This document
extends that foundation from *addressing by name* to *routing by name*.

---

## 1. Motivation

### 1.1 What IP got right, and why

The Internet Protocol scales to billions of endpoints because of one property:
**hierarchical numeric aggregation**. A backbone router does not store a route
to every host. It stores a route to a *prefix* — `192.0.2.0/24` — and forwards
every address inside that block the same direction. Prefixes nest, so a
tier-1 router summarizes enormous swaths of the address space in a single
forwarding entry and matches them at line rate with fixed-width longest-prefix
logic in dedicated silicon.

This is the property any replacement must reproduce. A routing scheme without
aggregation requires a forwarding entry per destination, which does not scale
past a small network. Aggregation is not an optimization; it is the load-bearing
wall.

### 1.2 What IP got wrong, for humans

The same numeric addresses that route beautifully are hostile to people. They
carry no meaning, cannot be remembered, must be translated by a separate system
(DNS) that goes stale for hours at a time, and encode identity nowhere — an IP
proves a packet reached *an address*, never *who answered*. Worse, address
scarcity produced NAT, and NAT produced a generation of port-forwarding,
DDNS, and VPN complexity whose sole purpose is to undo the damage of hiding
machines behind shared numbers.

DNX begins from a simple observation: **names already form a hierarchy.** The
same tree structure that lets DNS delegate `dnxroute.com` to its owner could,
if read at forwarding time, let a router aggregate. The question this document
answers is: *what must a name look like, and how must a router read it, for
name hierarchy to do the job numeric hierarchy does today?*

### 1.3 The thesis

> Replace the aggregation key. Keep hierarchy; change hierarchy's alphabet from
> numeric prefixes to name suffixes. Geography, which IP delivers by accident of
> allocation, DNX delivers by design of the namespace.

---

## 2. Addressing model

### 2.1 Two faces of a name

DNX separates what a human uses from what a router forwards on — the **hybrid
model**. A single logical endpoint has:

- a **human FQDN**, familiar and backward-compatible, read small→big as in DNS:
  `host1.disa.dnxroute.com`;
- a **routing locator**, an ordered tier path read big→small, coarsest tier
  first: `dnx / us-east / gov / disa / host1`.

The registry — already central to DNX identity — binds a name to *both* its
cryptographic key and its locator. Resolution therefore returns not just "who
is this and where is its endpoint," but "**how does the network route toward
it.**"

### 2.2 The locator

A locator is an ordered sequence of **tiers**, most-significant first:

```
dnx . <region> . <authority> . <site> [. <sub> ...] . <host>
└─┬─┘   └──┬───┘    └───┬────┘   └─┬──┘              └──┬─┘
 root   region hub   authority   site               leaf
```

- **Direction.** The locator is written big→small, the *opposite* of a DNS
  name, because routers must match the coarsest, most-aggregatable tier first.
  A core router cares only that a packet is bound for `us-east`; it neither
  reads nor stores the tiers below.
- **Variable depth.** A locator carries between one and N tiers below the root.
  A small deployment may be shallow (`dnx/us-east/host`); a large authority may
  be deep (`dnx/us-east/gov/disa/bldg4/host`). Depth is a property of the
  endpoint, not a global constant — exactly as DNS labels vary in count.
- **Root.** The single reserved top tier `dnx` anchors the hierarchy and is the
  default route: a router that recognizes no tier forwards upward toward root,
  guaranteeing a path to a router that does.

### 2.3 Point-of-presence, not passport

A locator declares **where a name routes**, which its owner chooses — precisely
as one chooses where to rent a server. A Russian citizen may buy a US VPS;
packets to that VPS route to the US datacenter, because the *locator of the
machine* is US, regardless of the owner's nationality. DNX locators work
identically: the tier path reflects the endpoint's declared point-of-presence,
assigned at registration, not the registrant's identity or citizenship.

This dissolves the naive objection that "TLDs aren't geographic." Correct —
legacy TLDs are not, and DNX does not use them for routing. DNX routes on a
locator hierarchy it defines and controls, in which each tier *is* a routing
locator by construction. The human FQDN (`…dnxroute.com`) remains for people;
it is not what the network forwards on.

---

## 3. Forwarding

### 3.1 Longest-suffix match

IP forwards by longest-*prefix* match: the most specific numeric block wins.
DNX inverts this to longest-*suffix* match over locator tiers, evaluated
most-significant tier first. Each router holds a **tier forwarding table**
(the DNX analogue of a FIB) mapping a tier value it is responsible for to a
next hop:

```
Core router (root tier)         Region hub (us-east)          Site router (disa)
  us-east   -> hub-east           gov       -> gov-gw            bldg4 -> sw-4
  us-west   -> hub-west           edu       -> edu-gw            host1 -> :local
  eu-west   -> hub-eu             disa      -> disa-rtr          host2 -> :local
  *         -> uplink(root)       *         -> uplink            *     -> drop
```

A packet for `dnx/us-east/gov/disa/host1` is forwarded thus:

1. **Core** reads the highest unresolved tier, `us-east`, matches it to
   `hub-east`, and forwards. It never reads `gov`, `disa`, or `host1`.
2. **Region hub** reads the next tier, `gov`, forwards to `gov-gw`, which
   reaches `disa-rtr`.
3. **Site router** reads `disa` then `host1`, and delivers locally.

Every hop consumes exactly the tiers it owns and ignores the rest. No hop reads
the whole locator; none reads an IP address for its DNX decision.

### 3.2 The forwarding algorithm

```
forward(packet):
    loc   = packet.locator            # ordered tiers, big->small
    tier  = loc.highest_unresolved()  # the coarsest tier not yet consumed
    hop   = fib.lookup(tier)          # exact match on this tier's value
    if hop is LOCAL:
        deliver(packet)               # this router owns the leaf
    elif hop is not None:
        packet.mark_resolved(tier)    # descend one tier
        send(packet, hop)
    else:
        send(packet, fib.default)     # unknown tier -> toward root (default route)
```

A single exact-match lookup per hop, on one tier, against a table whose size is
the number of *distinct child tiers at that router* — not the number of hosts.
This is what makes it tractable (§4).

### 3.3 Resolution vs. forwarding

DNX cleanly separates the two operations legacy networking entangles:

- **Resolution** (registry): name → (key, locator, endpoint). Done once,
  cached, refreshed by heartbeat. Answers "who and where."
- **Forwarding** (routers): move a packet toward a locator, hop by hop.
  Answers "which way."

DNS+IP couples these badly: you resolve a name to an address, then route the
address, and if the host moves, the stale address routes you to the wrong place
until a TTL expires. DNX forwards on the locator hierarchy directly, so
mobility within a tier (a host moving inside `disa`) never invalidates the
coarse routes above it.

---

## 4. Aggregation analysis — why this scales

The claim that name hierarchy aggregates as well as numeric hierarchy is the
paper's technical crux. State it precisely.

Let the network have H hosts arranged in a tree of branching factor b and depth
d, so H ≈ b^d. Consider a router at tier level k (0 = root).

- **Its forwarding table size** is the number of distinct child tiers it must
  distinguish: **b entries**, independent of H.
- **A core (root) router** holds one entry per top-level region — a few dozen —
  and forwards all H hosts through them. Aggregation ratio: H : (regions).
- **Table growth** as the network adds hosts is **zero at the core**: new hosts
  appear as new leaves under existing region/authority tiers already present in
  core tables. The core learns nothing new.

Compare IP: a core router's table grows with the number of *allocated prefixes*,
today ~1M routes and climbing, because allocation is fragmented and prefixes
deaggregate. DNX tables are bounded by the *designed branching factor of each
tier*, not by allocation history. A human-designed hierarchy can be kept shallow
and wide at the top (few large regions) and deep only where locality is dense —
producing core tables **smaller** than IP's, by construction.

> **Result.** DNX forwarding-table size at any router is O(children-of-that-router),
> not O(hosts) and not O(allocated-prefixes). The core is constant in the number
> of hosts. This is the property that makes name-hierarchical routing viable.

### 4.1 The cost, stated honestly

Longest-suffix match on variable-length string tiers is more expensive *per
lookup* than fixed-width numeric prefix match in TCAM silicon. DNX trades a
harder per-hop lookup for smaller tables and human-meaningful routing. The
whitepaper must quantify this; the PoC (§7) measures it in software. Hardware
acceleration of suffix matching is prior-art-adjacent (NDN name-based FIBs,
trie/hash hybrids) and is addressed in future work, not hand-waved.

---

## 5. Objections and answers

A whitepaper survives peer review only by meeting its hardest objections in the
open. The four that sink naive name-routing proposals, and DNX's answers:

**O1 — "TLDs aren't geographic; `.com` is global."**
Correct, and DNX does not route on legacy TLDs. It routes on a locator
hierarchy it defines, where each tier is a routing locator by construction
(§2.3). The human FQDN is decorative to the router.

**O2 — "Variable-length string matching can't run at line rate."**
Acknowledged as the real cost (§4.1). DNX's answer is threefold: (a) tables are
far smaller, so more fits in fast memory; (b) each hop matches *one tier*, not
the whole name; (c) suffix matching maps onto existing trie/hash techniques from
NDN and IP-lookup literature. Quantified in the PoC; hardware path in future
work. This is an engineering problem, not a correctness one.

**O3 — "Aggregation breaks when a host moves or multi-homes."**
Movement *within* a tier is invisible to routers above it — the coarse routes
still point at the right region/authority; only the owning site updates. This is
strictly better than IP, where moving across a prefix boundary requires
renumbering or triangular routing. Multi-homing is expressed as a name with
multiple locators, resolved by policy — specified in the full paper.

**O4 — "You still ride IP, so you haven't replaced anything."**
True and intentional. DNX v0.x is an **overlay**: DNX packets travel in UDP/IP
today, exactly as IP itself first traveled over the phone network before
IP-native hardware existed. The overlay is the deployment on-ramp, not the end
state. DNX-native forwarding — routers making decisions solely on locators — is
specified as the target architecture; the overlay proves the model while the
migration path (§6) makes it deployable without a flag day.

---

## 6. Backward compatibility and deployment path

DNX is designed to deploy *incrementally*, never requiring a flag day:

- **Stage 0 — Overlay (today).** DNX runs on UDP/IP. Locators are carried in the
  DNX header; forwarding between DNX routers is by locator, but each DNX hop is
  reached over ordinary IP. Zero changes to existing infrastructure. *(Implemented
  through the session layer; §7 adds the router.)*
- **Stage 1 — DNX islands.** Organizations run DNX-native routers internally
  (a campus, a datacenter, a DoD enclave), bridging to the global internet via
  overlay at the edge. Locator routing is real inside the island; IP is the
  inter-island transport.
- **Stage 2 — DNX peering.** Islands peer directly over DNX at exchange points,
  forwarding by locator across organizational boundaries. IP remains as fallback
  transport where DNX peering is absent.
- **Stage 3 — DNX-native substrate.** Where density justifies it, hardware
  forwards on locators directly. IP becomes the legacy underlay, then optional.

At every stage, a DNX name resolves and routes; the only thing that changes is
how much of the path is locator-native versus IP-underlaid. Backward
compatibility with TCP/IP is thus not a feature bolted on but the deployment
strategy itself.

---

## 7. Proof of concept — what must be demonstrated

The concept is only real if a packet reaches its destination by locator
forwarding across multiple hops, with no DNX-layer IP routing decision. The PoC
`dnx-router` must show:

1. **Multi-hop locator forwarding.** A ≥4-node software topology (core → region
   → site → host) forwarding a sealed DNX frame from source to destination
   purely by longest-suffix match. Instrumentation logs, at each hop, *which
   tier it matched and why* — proving no hop reads the whole name or an IP for
   its decision.
2. **Aggregation, observed.** The core router's table holds one entry per region
   while multiple hosts route through it, demonstrating O(children) table size
   empirically, not just in analysis.
3. **Default-route ascent.** A packet for an unknown tier ascends toward root and
   is correctly dropped or redirected, proving the default-route mechanic.
4. **Security preserved.** Frames remain ChaCha20-Poly1305 sealed end to end;
   routers forward on the *locator* (header, authenticated) without decrypting
   payload — DNX routers are blind carriers, like IP routers, but cryptographically
   so.
5. **Measured cost.** Per-hop lookup latency reported, so §4.1's honesty is
   backed by numbers.

Delivery: `dnx-router` binary + a scripted topology + a captured run showing the
tier-by-tier forwarding trace and the aggregation table. That captured run is the
figure the whitepaper is built around.

Two implementations exist: `cmd/dnx-router` is the single-process software
simulation described above; `cmd/dnx-routerd` is a *distributed* daemon — one
process per physical machine, forwarding real UDP frames across the actual
internet — deployed live at registry.dnxroute.com and routing.dnxroute.com.

---

## 8. Relationship to prior work

DNX is not the first name-oriented network, and the paper must place it honestly:

- **Named Data Networking (NDN) / CCN.** Shares name-based forwarding and
  name-based FIBs; differs in that NDN routes on *content names* toward data,
  pull-style, whereas DNX routes on *endpoint locators* toward hosts, preserving
  a host-to-host model and thus a simpler mental and deployment story. DNX borrows
  NDN's FIB techniques for §4.1.
- **ILNP (Identifier/Locator Network Protocol).** Shares the identifier/locator
  split; DNX makes the locator a *routable name hierarchy* rather than a numeric
  locator, and binds the identifier to a cryptographic key natively.
- **DNS + IP.** DNX collapses the resolve-then-route split (§3.3) and removes the
  TTL-staleness and NAT-complexity that the DNS+IP division produces.
- **HIP, WireGuard's key model.** DNX's name→key identity and its handshake draw
  on the same cryptographic identity thinking; DNX's contribution is fusing that
  identity to a *routable* name.

*(Citations above are drawn from general knowledge and need verification against
current literature before formal publication.)*

---

## 9. Status and next steps

**Implemented and deployed:** registry, cryptographic name→key identity, NAT
traversal, X25519 handshake, ChaCha20-Poly1305 session layer, live at
`registry.dnxroute.com`; distributed 256-bit locator routing across two nodes,
live at `routing.dnxroute.com`.

**This document specifies, and the PoC demonstrates:** the locator hierarchy,
longest-suffix forwarding, aggregation, and the deployment path.

**Immediate next step:** encrypted stream layer (reliable delivery inside the
sealed channel), then `dnx tunnel`, culminating in an SSH session carried
entirely over DNX. Fold results into the full whitepaper, of which this concept
doc is the spine.

---

*DNX is an experimental protocol. Every implemented claim above corresponds to
running code; every unimplemented claim is marked as specification or future
work. Where this document and the code disagree, the code is the bug.*
