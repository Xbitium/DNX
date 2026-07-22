# Deployment

The configuration that runs the public DNX deployment. Binaries are built
from `cmd/`; everything here is what makes them run.

## The two hosts

Naming is confusing and worth stating plainly once, because the machine
hostnames and the DNX names do not line up:

| Address | Machine hostname | DNX name | Runs |
|---|---|---|---|
| `142.93.177.59` | `dnxroute2` | `dnxroute2.internal.dnxroute.com` | registry, nginx (`dnxroute.com`, `routing.dnxroute.com`), node agent, router daemon |
| `134.122.7.99` | `dnxroute1` | `dnxroute1.internal.dnxroute.com` | node agent, router daemon |

`registry.dnxroute.com` resolves to `142.93.177.59`. That is the only place
legacy DNS appears in DNX: it is how a node finds the registry at boot.

## What is NOT in this directory, deliberately

- **The registry's private signing key** (`/var/lib/dnx/registry.key`, mode
  0600). Its public half appears in the unit files as `--registry-key`, which
  is exactly where it belongs — nodes need it to verify answers.
- **Node identity keys** (`/root/.dnx/identity.json`, mode 0600). These *are*
  the machines. A node that lost one would come back with a new key and be
  refused its own name, because the registry binds a name to a key for a year.
  Back them up somewhere other than a public repository.
- **TLS certificates** (`/etc/letsencrypt/...`). Managed by certbot; the
  nginx configs reference them by path.
- **Persisted name ownership** (`/var/lib/dnx/registry.json`). Runtime state,
  not configuration.

## Layout

```
systemd/    unit files, one per service per host
nginx/      vhosts for dnxroute.com and routing.dnxroute.com
scripts/    the deploy scripts used for each upgrade
node1.json  router daemon topology, 142.93.177.59
node2.json  router daemon topology, 134.122.7.99
*-dual.json the same topology carrying both wire formats (DNXP-0001)
```

## Rebuilding a host from scratch

1. Install the binaries to `/usr/local/bin` (`dnx-registry`, `dnxd`, `dnx`,
   `dnx-routerd` as appropriate for that host).
2. Copy the matching unit file to `/etc/systemd/system/`.
3. `mkdir -p /var/lib/dnx && chmod 700 /var/lib/dnx`.
4. Restore the node's identity key, or accept that it will claim a new name.
5. `systemctl daemon-reload && systemctl enable --now <service>`.
6. For the web host, copy the nginx vhosts, symlink into `sites-enabled`,
   and run certbot for the two domains.

## Firewall

Both hosts run `ufw`. Open ports:

| Port | Purpose |
|---|---|
| 22/tcp | SSH |
| 80,443/tcp | nginx (`142.93.177.59` only) |
| 4400/udp | registry (`142.93.177.59` only) |
| 4500/udp | router daemon, inter-node forwarding |
| 4600/tcp | router telemetry, restricted to the other host's address |

Node agents need no inbound rules at all. Every DNX path is initiated
outbound from both ends, which is why a fully firewalled node is still
reachable by name.

## Upgrade order

The registry signs the answers nodes verify, so it goes first. A node
without `--registry-key` still works and logs a warning, which is what makes
the rollout incremental rather than a flag day.

1. Registry, then confirm `restored N name binding(s)` in its log.
2. Node agents, adding `--registry-key` from the registry's startup log.
3. Confirm with `dnx ping <peer>` — expect `identity_verified=true
   encrypted=true`.

Each script keeps the previous binary as `.prev` alongside it, so a rollback
is one `install` and a restart.
