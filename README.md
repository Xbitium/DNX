# DNX — Domain Native eXchange

An experimental identity-native networking protocol. Names are the address:
every DNX endpoint registers a fully-qualified domain bound to an ed25519
keypair, and every reply is cryptographically verifiable against the key
that owns the name — no visible IPs, no NAT configuration, no port
forwarding.

**Live:** [dnxroute.com](https://dnxroute.com) · protocol spec at
[dnxroute.com/protocol](https://dnxroute.com/protocol) · a live, public,
cross-datacenter routing demo at
[routing.dnxroute.com](https://routing.dnxroute.com)

## Status

DNX is a working prototype, not a finished protocol. What's implemented and
deployed today:

- **Identity & rendezvous (v0.1):** a living registry binds names to ed25519
  keys, with NAT hole punching for direct peer-to-peer reachability.
- **Encrypted sessions (v0.2):** X25519 handshakes authenticated by the
  registered identity key, ChaCha20-Poly1305 sealed channels, 5-minute
  forward-secret rekeying.
- **Name-hierarchical routing (v0.3, PoC):** a 256-bit structured address
  derived from the name hierarchy (`TLD`/`domain` registry-assigned,
  `subdomain`/`host` hash-derived), forwarded by routers that read one
  64-bit field per hop — the same fixed-width operation IP silicon already
  does, extended to be name-meaningful.

Read [`docs/dnx-routing-concept.md`](docs/dnx-routing-concept.md) for the
full addressing/routing model, the aggregation analysis, and an honest
account of what this does and does not claim to replace.

## Repository layout

```
cmd/
  dnx/            CLI — dnx ping <name>, dnx status
  dnxd/           node agent — identity, heartbeat, NAT punch, v0.2 sessions
  dnx-registry/   the living name → (key, endpoint) registry
  dnx-router/     single-process PoC: 256-bit address forwarding, in-process
  dnx-routerd/    distributed router daemon — what actually runs in production,
                  one process per physical node, forwarding real UDP frames
                  across the internet by 256-bit field match
internal/
  proto/          v0.1 wire message envelope + signing
  identity/       ed25519 keypair generation & persistence
  secure/         v0.2 session layer: X25519 handshake, ChaCha20-Poly1305
  locator/        text-tier locator + longest-suffix forwarding (early PoC)
  dnxaddr/        256-bit structured address: the hybrid allocation model
docs/
  dnx-routing-concept.md   the routing whitepaper's spine
deploy/
  node1.json, node2.json   reference dnx-routerd topology configs
site/
  the public site + the live routing dashboard (routing.html)
```

## Building

```bash
go build ./...
```

Requires Go 1.23+. Binaries land as `dnx`, `dnxd`, `dnx-registry`,
`dnx-router`, `dnx-routerd` under whatever `-o` path you give `go build`.

## Running the single-process routing PoC

```bash
go run ./cmd/dnx-router          # human-readable forwarding trace
go run ./cmd/dnx-router --json   # machine-readable trace
```

This builds a small in-process topology (core → domain → subdomain → host)
and forwards a sealed frame to `host1.dnx.dnxroute.com` purely by 64-bit
field match, then shows the core's aggregation table and a clean drop for
an unallocated name.

## Running a live node

```bash
go build -o dnxd ./cmd/dnxd
./dnxd --name yourmachine.internal.dnxroute.com --registry registry.dnxroute.com:4400

go build -o dnx ./cmd/dnx
./dnx ping dnxroute1.internal.dnxroute.com
```

## Security model, stated plainly

- Names bind to keys first-come-first-served at the registry; a name can
  never be re-bound to a different key.
- Session keys are ephemeral (X25519) but authenticated by the long-term
  ed25519 identity, so a session is provably owned by whoever owns the name
  — and forward secrecy holds because ephemerals are discarded every 5
  minutes.
- **Known v0.1/v0.2 gaps**, listed without spin in the concept doc: registry
  responses aren't yet signed, `PUNCH` cues aren't yet signed, the registry
  is a single point of failure, and name allocation is first-come-first-served
  with no squatting protection. None of this is hidden — see §6.4 of the
  concept doc.

## License

Not yet finalized — see the repository's LICENSE file once added, or open an
issue if you're evaluating this for a project and need clarity sooner.

## Contributing

This is early, experimental, and evolving fast. Issues and discussion are
welcome. There's no formal contribution process yet.
