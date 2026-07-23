# DNX: Identity-Native Networking over a Name Hierarchy

**A working draft describing running code**

Version 0.4 · July 2026 · [dnxroute.com](https://dnxroute.com) ·
[github.com/Xbitium/DNX](https://github.com/Xbitium/DNX)

---

## Abstract

DNX is an experimental network protocol in which a fully-qualified domain
name is simultaneously an identity, a routing destination, and a unit of
delegated authority. A machine registers a name bound to an ed25519 keypair;
resolution returns that key alongside a live endpoint; sessions are encrypted
with keys derived from a handshake the key authenticates; and packets are
forwarded by walking the name's own hierarchy, one level per hop.

The claim is deliberately narrow. DNX does not replace IP forwarding — its
packets travel as UDP datagrams over existing infrastructure. What it
replaces is the *aggregation key*: where IP derives routability from numeric
prefixes assigned by allocation policy, DNX derives it from a namespace
hierarchy that already exists for administrative reasons. Geography that IP
delivers by accident of allocation, DNX delivers by construction.

Everything described here as implemented is running. A registry, two node
agents and a router daemon are deployed across two datacenters; encrypted
sessions carry TCP traffic including SSH; and a public demonstration forwards
packets by name across the open internet. Sections are marked to distinguish
what runs from what is specified but unbuilt, and a security analysis
enumerates the protocol's known weaknesses, including one that was discovered
during this work and is described in full.

---

## 1. Motivation

### 1.1 The Internet is largely made of compensations

Almost every layer added to networking since the 1980s exists to recover
something the network itself does not know.

Network address translation exists because addresses ran out. Virtual private
networks exist substantially because NAT destroyed inbound reachability.
Transport Layer Security exists because an address proves nothing about who
answered it. The Domain Name System exists because numbers are unusable by
people. Dynamic DNS exists because addresses move. Relay and rendezvous
services exist because two machines behind NAT cannot find each other.

Each of these works. Together they mean that a modern connection is a stack
of compensations, and after all of them the network still cannot answer the
simplest question anyone asks of it: *who is this?*

### 1.2 What IP got right

Any proposal in this space must first respect why the incumbent works.

IP scales to billions of endpoints because of hierarchical numeric
aggregation. A backbone router does not store a route to every host; it
stores a route to a prefix and forwards everything inside that block the same
direction. Prefixes nest, so a small number of forwarding entries covers an
enormous address space, and the match is fixed-width and implementable in
dedicated silicon.

**Aggregation is not an optimisation. It is the load-bearing wall.** A
routing scheme without it needs a forwarding entry per destination, which
does not survive contact with a network of any size. This is the bar.

### 1.3 What names already have

Names are hierarchical, and that hierarchy already reflects organisational
reality: `host.team.division.company` describes a tree that exists whether or
not the network uses it. DNS uses this structure for *delegation* — deciding
who may answer — and then discards it: the moment a name becomes an address,
every router afterwards sees only numbers.

DNX asks what happens if the name keeps mattering all the way down.

### 1.4 Thesis

> Replace the aggregation key. Keep hierarchy; change its alphabet from
> numeric prefixes to name levels. Bind identity into the address rather than
> layering it above.

---

## 2. Goals and non-goals

**Goals.**

1. Names are the only addresses humans or applications handle.
2. Identity is native to the addressing layer: reaching a name and verifying
   its owner are the same operation.
3. A machine behind an unconfigured NAT is as reachable as a public server.
4. Records are fresh within seconds, not cache lifetimes.
5. Authority is delegable, so no single party controls the namespace.
6. Deployment is incremental; nothing requires a flag day.

**Non-goals.**

DNX does not replace IP forwarding. Packets are UDP datagrams moved by
existing routers. Name-native forwarding in hardware is a target
architecture, not a current claim, and section 11 is explicit about what that
would require.

DNX is not an anonymity system. It conceals payloads, not relationships; a
registry observes who resolves whom. Where anonymity is the requirement, Tor
is the correct tool and DNX is the wrong one.

DNX is not production software. It is an unaudited research prototype with a
wire format that will change.

---

## 3. Identity

### 3.1 The key is the machine

On first boot a node generates an ed25519 keypair. The keypair is the
machine's identity; the domain name is a human-readable handle bound to it.
The private key is stored locally, mode 0600, and never transmitted — only
public keys and signatures cross the wire.

A name binds to a key first-come-first-served. A registration for an
already-bound name under a different key is rejected regardless of signature
validity: possession of a name requires possession of its key.

### 3.2 Ownership is not liveness *(implemented)*

Two lifetimes run independently, and conflating them produced a real
vulnerability during development.

An **endpoint** expires 60 seconds after the last heartbeat, so nobody is
directed to a machine that has moved or gone away. A **name-to-key binding**
persists for a year and is then retired deliberately.

An earlier implementation deleted the whole record after ten minutes of
silence. The consequence was that switching a machine off for long enough
handed its name to whoever registered next, and the rightful owner was
subsequently refused its own name. Ownership had become a function of uptime.
Bindings are now persisted to disk with an atomic write, so they survive a
process restart as well; without that, deploying the first fix would itself
have un-owned every name in existence.

### 3.3 Transfer and release *(implemented)*

Two mechanisms, split by what cryptography can prove.

**Rotation** is a protocol feature. A `REBIND` message signed by the *current*
key transfers a name to a new one. Its signature covers the destination key,
not merely the name — a signature saying "move this name" without saying
where would let anyone observing one legitimate transfer replay it to install
a key of their own.

**Recovery from a lost key is not a protocol feature.** If an owner cannot
sign, nothing distinguishes them from an impostor making the same claim.
Releasing a name is therefore an operator action requiring shell access to
the registry host, and is deliberately unreachable over the network.

---

## 4. The registry

### 4.1 Three jobs

Calling it "the registry" obscures that one service currently performs three
functions with unrelated trust, scale and freshness characteristics:

| Job | Answers | Changes | Analogue |
|---|---|---|---|
| Naming authority | who owns this name? | almost never | a domain registrar |
| Location directory | where is it now? | constantly | an ARP table |
| Rendezvous broker | introduce these peers | per connection | STUN / signalling |

The first is an authority question and must be answered consistently. The
second is soft state that expires by itself. The third holds nothing. In a
mature deployment these are three services, possibly operated by three
parties.

The location directory is genuinely ARP-shaped: soft state about liveness,
refreshed by activity, expiring on silence. The decisive difference is that
ARP has no concept of ownership — whoever answers is believed, which is
precisely why ARP spoofing works. A DNX name is bound to a key, so answering
is not enough; you have to sign.

Routers never consult the registry to forward a packet. It is control plane,
not data plane.

### 4.2 The endpoint is observed, not asserted

A node never states where it is. The registry records the source address it
observed on the datagram, and that field is deliberately excluded from the
node's signature. A node therefore cannot lie about its location, because it
never claims one. For a NAT'd machine the observed address is the router's
public mapping, and the same heartbeat that reports presence keeps that
mapping alive.

### 4.3 Signed answers *(implemented)*

A resolution answer carries the peer's public key, and the asking node has no
other source for it. The handshake is then checked against exactly that key.

This is circular unless the answer itself is authenticated, and until it was,
an on-path attacker forging a single UDP packet could supply a key it
controlled, complete a valid handshake, and be reported as verified. Section
10.1 describes the discovery in full because the reasoning matters more than
the fix.

The registry now holds a persisted keypair and signs answers over the target
name, the peer's key and the endpoint — the three fields an attacker would
forge. A node configured with the registry's public key refuses any answer it
cannot verify.

### 4.4 Federation *(implemented and deployed)*

The unit of authority is a **zone**. A registry is authoritative for a zone
and may delegate branches to other registries; a resolver follows referrals
until it reaches an authoritative answer. This is DNS's delegation model,
with one addition: because DNX records carry keys, a referral can be signed,
so the whole chain is verifiable rather than trusted hop by hop.

A referral is a transfer of trust, and three conditions are enforced:

1. **It is signed** by the registry currently trusted. `ReferralBytes` covers
   the child's address *and* its key, because a referral naming only a zone
   would let a captured one point a resolver at any registry — the same
   substitution attack as a forged answer, one level up, and worse, since it
   hands over a branch rather than a name.
2. **The delegated zone contains the name asked about**, or the referral is
   simply misdirection.
3. **Each hop narrows.** A registry given `eng.example.com` cannot refer for
   `example.com`, a sibling, or anything unrelated. Without this, delegating
   a small part of a namespace would be a route to seizing all of it.

Containment is compared label-wise. A plain suffix test reports that
`evil-example.com` ends with `example.com`, which would hand authority to
whoever registered a similar-looking name. Delegations are also validated at
startup, so a misconfiguration is a boot failure rather than a hole nobody
notices.

### 4.5 The caching tension

Records are fresh within seconds only because every resolution reaches the
authoritative registry. Introducing caching for scale reintroduces the
staleness DNX criticises DNS for.

The resolution is that the two halves of a record have opposite profiles. A
**name-to-key binding** is stable, self-verifying, and safely cached for
days. A **name-to-endpoint mapping** is volatile and should be cached
briefly or not at all. Splitting the record splits the problem — and
reinforces the argument that the naming authority and the location directory
want to be separate services.

---

## 5. NAT traversal *(implemented)*

NATs were never blocking inbound traffic; they were blocking *unexpected*
inbound traffic. DNX makes every connection expected at both ends
simultaneously.

A node asks the registry to introduce it to a peer. The registry forwards a
cue to the peer's last observed endpoint — reachable because the peer's own
heartbeats keep that path warm — and both nodes then fire datagrams at each
other. Each outbound packet installs a mapping in its own NAT permitting the
other side's inbound traffic. The walls open from the inside.

Consequently a node needs **no inbound firewall rules at all**. In the live
deployment one host permits only SSH inbound and is still fully reachable by
name.

This succeeds against full-cone and port-restricted NATs. **Symmetric NATs**,
which allocate a fresh mapping per destination, defeat it; relayed fallback
is specified but not built, and peers behind such a NAT currently cannot
connect.

---

## 6. Session layer *(implemented)*

Two messages, approximately one round trip:

```
A → B   HS_INIT  { ephA_pub, nonce_A, ts, sig_A }      signed by A's ed25519
A ← B   HS_RESP  { ephB_pub, nonce_A, nonce_B, sig_B } signed by B's ed25519

both:   shared = X25519(eph_priv, peer_eph_pub)
        keys   = HKDF-SHA256(shared, salt = nonce_A ‖ nonce_B, info = direction)
```

The long-term identity key signs the ephemeral key. Since the registry binds
that identity key to a name, the session key is provably owned by whoever
owns the name: **encryption inherits name-identity, and nothing new has to be
trusted.** The registry never sees a session key.

Echoing `nonce_A` binds the response to that exact handshake. Each side
derives directional keys, so the two flows never share a nonce space.

Ephemeral keys are discarded on rekey every five minutes, so compromising a
machine's long-term key tomorrow does not decrypt traffic captured today.

Traffic is sealed with ChaCha20-Poly1305. The frame header carries a
monotonic counter that doubles as the AEAD nonce and is authenticated as
additional data; a counter is accepted at most once, and recorded only after
the tag verifies, so forged frames cannot poison the replay table.

**Design rule.** The protocol is ours; the mathematics is not. X25519,
ChaCha20-Poly1305, HKDF and ed25519 come from audited implementations. The
novel work is the state machine and how it inherits name-to-key trust — and
that is where the tests are aimed: impersonation with the wrong key, single-bit
tampering, replay, counter reuse across a thousand frames, and decryption by
a foreign session.

---

## 7. Stream layer *(implemented)*

DNX must run on UDP for NAT traversal, so something has to restore reliable
ordered delivery. The stream layer is deliberately TCP-shaped, because TCP's
shape is correct: byte-offset sequence numbers so segment boundaries may
change on retransmit, cumulative acknowledgement, RTO estimation from
smoothed round-trip time and variance with exponential backoff, a
receiver-advertised window, and slow start with multiplicative decrease on
loss. Round-trip samples are taken only from segments never retransmitted,
since a retransmitted segment's timing is ambiguous.

**Deliberately omitted:** selective acknowledgement, fast retransmit on
duplicate acknowledgements, path MTU discovery, and window scaling. Loss
recovery is timeout-driven — correct, but slower than TCP on lossy paths.

### 7.1 The zero-window deadlock

One behaviour is worth describing because it is invisible until provoked.

When a receiver's buffer fills, it advertises a zero window and the sender
parks. When the application finally reads, the receiver sends an
acknowledgement announcing the reopened window. **If that acknowledgement is
lost, both sides wait forever** — the receiver believes it announced space,
the sender is waiting to be told.

A test written specifically to provoke that sequence deadlocked exactly as
feared. The fix is TCP's persist timer: probe a closed window periodically so
that any reply carries the current state. It was verified by disabling the
probe and confirming the test fails, then re-enabling it.

### 7.2 Tunnels *(implemented)*

`dnx tunnel host.example.com 2222:22` opens a local TCP listener whose bytes
travel as stream frames inside the sealed session. Multiple tunnels are
multiplexed over one session by stream identifier. This has carried HTTP and
SSH in the live deployment.

Inbound tunnels are gated by an explicit **port allowlist**, and the design
of that flag matters. A boolean "tunnels enabled" switch published every
service bound to loopback — an administrative API, a database, a metrics
endpoint never meant to leave the machine — because the responder dials
whatever port the peer names. `--tunnel-ports 22` names what may be reached
and refuses everything else. A node given no ports refuses all inbound
tunnels, so the flag fails closed and upgrading without it changes no
exposure.

---

## 8. Routing

### 8.1 Forwarding by name level

Each router holds a table keyed by the single level of the destination it is
responsible for, mapping that level's value to a next hop. It reads that one
level, forwards, and never looks lower.

```
forward(packet):
    level = the level this router owns
    hop   = table.lookup(destination.at(level))
    if hop is LOCAL:   deliver
    elif hop exists:   mark level resolved; send to hop
    else:              no route — drop, definitively
```

**Authoritative failure matters.** A router responsible for a level is
authoritative for its children: if it has no route, nothing closer to the
root knows better, so the packet is dropped there. An earlier design
forwarded unmatched packets toward the root on the theory that something
higher would know more. It does not, and the result oscillated between two
routers until a hop limit killed it. "Send it upward and let someone smarter
decide" is not a routing policy; it is a loop with extra steps.

### 8.2 Why this aggregates

Let the network hold *H* hosts in a tree of branching factor *b*. A router's
forwarding table size is the number of distinct children it must
distinguish — *b* entries — **independent of H**. A core router holds one
entry per top-level namespace and forwards all *H* hosts through them.

Table growth at the core as hosts are added is **zero**: new hosts appear as
leaves beneath levels the core already knows. This is checked rather than
asserted — in test, a core table holds two entries after 1001 hosts are
added across two top-level namespaces.

Compare IP, where core tables grow with the number of *allocated prefixes*,
today around a million and climbing, because allocation fragments and
prefixes deaggregate. DNX table size is bounded by the designed branching
factor of each level, not by allocation history.

> **Result.** Forwarding-table size at any router is O(children-of-that-router),
> not O(hosts) and not O(allocated-prefixes). The core is constant in the
> number of hosts.

### 8.3 The cost, stated plainly

Matching a variable-length level is more expensive per lookup than a
fixed-width numeric prefix match in dedicated silicon. DNX trades a harder
per-hop lookup for smaller tables and human-meaningful routing.

The strongest evidence that this is implementable is MPLS, which has
forwarded variable-depth label stacks in hardware at line rate, in
essentially every large carrier network, for two decades. "Variable-depth
stack of small identifiers, each hop reading only the top one" describes MPLS
and DNX equally well.

That comparison also imposes an obligation: **how is DNX different from
MPLS?** MPLS labels are locally significant, signalled per path, and carry no
identity — they mean nothing outside the router pair that agreed on them. DNX
identifiers are derived from a namespace that means something everywhere and
are bound to keys. MPLS is a forwarding optimisation beneath IP; DNX changes
what is being forwarded on.

### 8.4 Namespace paths *(implemented; both formats run side by side)*

The original address was four fixed 64-bit fields. That capped hierarchy at
four levels and failed on the first realistic organisation chart —
`api.production.us-east.customer.company` is five.

A destination is now an ordered sequence of numeric identifiers with an
explicit count:

```
+---------+--------+--------+     +----------+
| count   | NID[0] | NID[1] | ... | NID[n-1] |
| 1 byte  | 4 bytes| 4 bytes|     | 4 bytes  |
+---------+--------+--------+     +----------+
```

**Identifiers are parent-scoped** — unique among siblings, not globally. This
is safe because forwarding is top-down: a router at level *k* only ever sees
packets whose levels 0…*k*−1 have already matched, so the parent context is
guaranteed. It keeps identifiers dense, and it removes a governance
objection: each namespace allocates its own without asking a central
authority for numbers.

The cost is that an identifier means nothing alone, which makes a misrouted
packet unreadable. Reverse resolution therefore exists, translating a path
back to the name it was addressed to and refusing to guess at identifiers
that were never allocated.

**Identifiers are never reused.** Reuse is the obvious way to keep them
dense and is a trap: a packet in flight, or a stale forwarding entry, would
be delivered to whatever inherited the number. Monotonic allocation is
simpler than generation counters and costs nothing at four billion
allocations per parent.

Decoding is strict — a truncated or over-deep path is refused rather than
half-interpreted, because guessing at a destination is how a packet ends up
somewhere nobody intended. Depth is capped at sixteen.

The common case is also *smaller* than what it replaces: 17 bytes at four
levels against a fixed 32, and 33 bytes at eight levels, a depth the old
format could not express at all.

Both formats currently run side by side under distinct frame markers, sharing
one forwarding walk — only the lookup key and table differ. This is what
makes the migration gradual rather than a flag day.

---

## 9. Wire formats

Four formats share one UDP socket, distinguished by their first byte, which
is what allows old and new to coexist during migration.

| First byte | Contents |
|---|---|
| `{` | JSON control message — registration, resolution, handshake |
| `0xD8` | Sealed frame — ChaCha20-Poly1305 |
| `0xDF` | Routed frame, fixed four-field address |
| `0xDE` | Routed frame, variable-length namespace path |

A control message carries the sender's name, its public key, a millisecond
timestamp enforced within ±30 seconds, a 96-bit nonce, and an ed25519
signature. The registry-observed endpoint is present but deliberately outside
the signed bytes.

A routed frame carries the destination, a count of levels already resolved so
the next router knows where to continue, and a payload that is itself a
sealed frame. **Routers forward what they cannot read.**

---

## 10. Security analysis

### 10.1 The impersonation hole

This is described at length because the reasoning generalises.

An early version of this documentation asserted that forging a resolution
answer permitted denial of service but not impersonation, on the grounds that
a poisoned endpoint could not produce replies verifying against the genuine
key.

**That was wrong.** It assumed an attacker would forge only the endpoint. A
resolution answer carries the peer's public key as well, and the asking node
has no independent knowledge of it — the handshake is checked against exactly
the key the registry just supplied. An on-path attacker forging one UDP
packet could therefore name a key it held, complete a valid handshake, and be
reported as `identity_verified=true` for a machine that did not own the name.

Every identity guarantee in the protocol rested on one unauthenticated
message. The fix is section 4.3.

The generalisable lesson concerns what a signature covers. The ordinary
message signature omits the key field, which is *correct* for registration —
the key is self-asserted and signing with it proves possession — and would
have been *catastrophic* if reused for a transfer or a referral, where the
key is precisely what an attacker would substitute. The same omission is
harmless in one message and fatal in another. Both `RebindBytes` and
`ReferralBytes` therefore define their own signing strings, and each is
verified by a test that removes the critical field and confirms the attack
succeeds without it.

### 10.2 What a verified reply proves

That the responder holds the private key the registry associates with that
name, and — where the registry's own key is configured — that the answer
naming that key was authentic. It does not prove anything about the peer's
intentions.

### 10.3 Known weaknesses

| Weakness | Consequence |
|---|---|
| **Symmetric NAT** | Simple hole punching fails; those peers are unreachable. Relayed fallback is specified, not built. |
| **No registry replication** | Federation splits authority, but each zone is still a single machine. Its loss halts *new* resolution and rendezvous; established sessions continue. |
| **Metadata exposure** | A registry observes who resolves whom. Delegation narrows each registry's view to its own zone but does not eliminate this. |
| **No ownership proof** | Nothing ties a DNX name to actual control of the corresponding domain, so any unclaimed name may be registered by anyone. |
| **No homograph policy** | Visually identical names built from different scripts are distinct names. |
| **Identity key loss** | A node that loses its key is refused its own name until an operator releases it. There is no backup mechanism. |
| **Zone identifier prefixes travel by configuration** | Leaf identifiers are now allocated by the registry and fetched, signed, by routers and nodes — configuration order no longer matters for them. What still travels by hand is one prefix per DELEGATED zone: the parent assigns it in its delegations file and the child operator copies it once, exactly as they already copy the child's endpoint and signing key. A child configured without its prefix numbers the branch differently from what the parent granted, and nothing detects that locally — the registries' published tables simply disagree. |
| **Unaudited** | The implementation has had no external review. |

This list is published because a protocol that conceals its weaknesses cannot
be evaluated. If a reader finds one absent from it, that is a defect in this
document.

---

## 11. Implementation and deployment

About 5,400 lines of Go across eight library packages, plus 3,100 lines of
tests — 100 test functions, concentrated where the consequences of being
wrong are worst: 37 in the registry, 20 in namespace paths, 16 in the node
agent, 12 in the stream layer, 7 in the session layer. Three binaries — registry, node
agent, router daemon — plus a command-line client.

Three packages carry no tests of their own: `identity` and `proto` are
exercised throughout the others, and `locator` is superseded by `nspath` and
retained only for reference.

**Deployed:** a registry with signed answers and persisted ownership; node
agents on two hosts in separate datacenters, both verifying registry answers;
encrypted sessions; NAT traversal; TCP tunnelling behind a port allowlist;
a public routing demonstration; and a federated namespace — a root registry
authoritative for `dnxroute.com` delegating `eng.dnxroute.com` to a second
registry in another datacenter, with resolvers following the signed referral;
and both wire formats at once — the same four routers forward a 32-byte fixed
address and a 17-byte namespace path concurrently, with no coordinated cutover.

**Built, not yet deployed:** the tunnel setup probe; and the routers'
fetch-from-registry mode — the registry authority itself is live (both
production registries allocate, persist, and publish, and a resolve
through the referral chain returns the child-allocated path verified),
but the public routing demonstration still derives its identifiers from
configuration order, because the names it routes are synthetic: no node
registers them, so no authority allocates them.

### 11.1 Measurements

All from the live deployment or its test suite; none are extrapolated.

| Measurement | Value |
|---|---|
| Encrypted ping, cold (includes handshake, cross-datacenter) | ~405 ms |
| Encrypted ping, warm (session reused) | ~1 ms |
| Cloud → residential NAT, first packet (includes traversal) | 396 ms |
| Same path, established | 49 ms |
| Referral + NAT punch, cold (root -> child registry -> NAT'd peer) | ~455-540 ms |
| Same referred path, established session | ~47 ms |
| Session handshake, same host | ~2 ms |
| Router lookup, single process | 0.03 – 1.5 µs |
| Core table after 1001 hosts, two top-level namespaces | 2 entries |
| Destination on the wire, four levels | 17 bytes (vs 32 fixed) |
| Stream integrity under 20% induced packet loss | no loss, no reordering |

### 11.2 Method

Nine substantive defects were found during development, each by asking what
happens in a case nobody had tested, and each fix verified by first watching
its test fail:

1. A routing loop from forwarding unmatched packets toward the root.
2. A zero-window deadlock when a window update is lost.
3. Name hijack: ownership expiring with liveness after ten minutes.
4. Namespace wipe: ownership held only in memory, lost on restart.
5. A three-label name copying its host label into its subdomain field.
6. Impersonation via unsigned resolution answers (section 10.1).
7. `dnx tunnel` reporting success for a tunnel the far end would refuse.
8. Rendezvous sent to the configured registry rather than the one a referral
   had made authoritative.
9. A request for one wire format answered in another, and reported as
   success, by a daemon too old to know the format existed.

Three are worth noting for how they were found. The subdomain defect surfaced
because a second implementation, written in JavaScript for a browser
playground, disagreed with the first — and the first was wrong. The
impersonation hole surfaced from re-reading a security claim in this
project's own documentation while preparing to build federation.

The eighth is the one this section's method exists to catch, and it very
nearly escaped. Following a referral moves authority to a child registry, but
`intro` — the request that asks a registry to cue a peer through its NAT —
took the configured registry unconditionally, because `resolve` never told
its caller where the chain had ended. All three call sites therefore made the
same mistake in the same direction: resolve through a delegation, then ask
the root for rendezvous, of a name the root has delegated away and holds no
endpoint for.

What makes it worth recording is the shape of the failure rather than the
fix. Two publicly-reachable peers never notice, because they do not need the
punch; only a peer behind NAT fails, which is precisely the case DNX exists
to serve and the one every demonstration here rests on. A defect invisible in
the easy path and fatal in the important one is the kind that reaches
production, and this one had: federation's referral-following code was
covered by seven tests that all ran at configuration-load time and never put
a referral on a wire. The fix makes the answering registry part of what a
resolution returns, so a caller cannot express the wrong thing; the tests
that now exist drive real sockets and assert where the rendezvous lands.

It was also falsified against the live deployment, which is the measurement
this section would otherwise be missing. A machine behind residential NAT was
registered under the delegated zone and addressed from a node in another
datacenter anchored at the root registry, so reaching it required following
the referral *and* punching the NAT through the child. On the pre-fix binary
the request failed with a handshake timeout; on the fixed binary, taken
moments later against the same peer, it verified in 49 ms. The control that
makes this conclusive ran on the pre-fix binary too: a peer in a
non-delegated zone answered normally throughout, so what failed was not the
node but specifically the combination of delegation and NAT.

The ninth is defect seven wearing different clothes, and it was found by deploying rather than by reading. A request to originate a packet as a namespace path was answered, by a router daemon predating that format, with a fixed address and a success reply — the format field it did not recognise simply fell through to the default. Nothing was wrong with the running system; it was doing what an older binary should do with a field it has never heard of. What was wrong was reporting that as the thing requested. Version skew is the ordinary condition of a network protocol, not an exceptional one, so an unrecognised format is now refused by name.

---

## 12. Related work

DNX is not the first name-oriented network and should be read as a descendant
of this literature rather than a rival to it.

**Named Data Networking / CCN** is the most serious existing attempt at
name-based forwarding, with name-based forwarding tables and research since
roughly 2009. NDN routes on *content* names toward data, pull-style; DNX
routes on *endpoint* names toward hosts, preserving a host-to-host model.
That makes DNX far less ambitious and considerably easier to deploy
incrementally. The literature on making name-based forwarding tables fast is
NDN's, and DNX borrows from it.

**ILNP, LISP and HIP** all separate identity from location, which is the same
instinct. They keep locators numeric and add a mapping layer; DNX makes the
locator a routable name hierarchy, so the thing routed on is the thing a
human reads. HIP is the closest relative on identity; DNX's contribution is
fusing that cryptographic identity to a locator that aggregates.

**MPLS** is the evidence that the forwarding model is implementable at line
rate (section 8.3).

**WireGuard** supplies the identity model DNX's session layer borrows —
"the keypair is the machine" is WireGuard's insight — but has no naming or
routing story; peers are configured with keys and endpoints by hand.

**Tailscale and ZeroTier** deserve the most attention from anyone evaluating
DNX, because much of what DNX demonstrates today they do in production. The
difference is structural: they are flat meshes whose coordinator knows every
node, and that knowledge grows with the number of machines. DNX's claim is
about hierarchy — a core table that does not grow as hosts are added beneath
it. Whether that matters depends on whether an overlay should scale like the
Internet or like a company network.

**SCION** reorganises inter-domain routing while keeping addresses roughly as
they are; DNX reorganises the address and lets the hierarchy route. They
attack different halves of the same discomfort, and SCION is vastly more
mature.

**DNS + IP** remains the incumbent, and its delegation model is what DNX's
federation imitates.

---

## 13. Limitations and future work

**Nearest term.** Retire the fixed four-field address: with identifiers now allocated by the registry and received over signed channels, the migration's blocker is gone and what remains is converting the data plane and deleting the old encoder. Then build relayed fallback so peers behind symmetric NATs can connect; and give a registry asked for a name outside its zone an explicit answer, since it currently stays silent and the resolver reports a timeout that reads as though the registry were unreachable.

**Then.** Registry replication, so a zone is not a single machine. A backup
and recovery story for node identity keys. Ownership proofs binding a DNX
name to demonstrated control of the corresponding domain. Selective
acknowledgement and fast retransmit in the stream layer.

**Research.** Pushing name-based forwarding down the stack, so routers decide
on names natively rather than over an IP substrate. This is a direction, not
a schedule, and the honest position is that the overlay is not a compromise
on the way there — it is how such things get deployed. IP itself first ran
over the telephone network, and nobody ever removed the copper; it simply
stopped being what anyone thought about.

---

## 14. Conclusion

DNX tests a narrow hypothesis: that the aggregation key can be replaced, that
identity belongs in the address rather than above it, and that both can be
deployed incrementally over the network that already exists.

The hypothesis is not proven. What exists is a working prototype, a public
deployment, a set of measurements, and a candid list of what remains broken.
That is offered not as a finished argument but as something concrete enough
to disagree with — which is the only useful thing an experimental protocol
can be.

---

*Every implemented claim corresponds to running code. Where this document and
the code disagree, the code is the bug. Corrections and objections are
welcome at [github.com/Xbitium/DNX](https://github.com/Xbitium/DNX).*
