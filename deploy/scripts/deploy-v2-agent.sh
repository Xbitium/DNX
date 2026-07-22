#!/usr/bin/env bash
# Upgrade a DNX node agent from v0.1 to v0.2 (encrypted sessions + streams).
#
# Deliberately does NOT enable --allow-tunnel: handleTunnelOpen dials any
# loopback port a peer names, which on a public box would expose nginx, the
# telemetry API and anything else on 127.0.0.1. That needs a port allowlist
# before it is safe to turn on here.
#
# The node's identity (~/.dnx/identity.json) is left untouched. It must be:
# the registry now binds a name to a key for a year, so a node that came back
# with a new key would be permanently refused its own name.
set -e

test -f /tmp/dnxd || { echo "FATAL: /tmp/dnxd missing"; exit 1; }
test -f /tmp/dnx  || { echo "FATAL: /tmp/dnx missing";  exit 1; }
chmod +x /tmp/dnxd /tmp/dnx

echo "=== identity BEFORE upgrade (must be unchanged afterwards) ==="
sudo test -f /root/.dnx/identity.json \
  && sudo sha256sum /root/.dnx/identity.json \
  || echo "  no identity at /root/.dnx — check the service's HOME"

echo
echo "=== current version behaviour ==="
sudo systemctl is-active dnxd || true

# rollback copies
sudo cp -f /usr/local/bin/dnxd /usr/local/bin/dnxd.prev 2>/dev/null || true
sudo cp -f /usr/local/bin/dnx  /usr/local/bin/dnx.prev  2>/dev/null || true
echo "rollback copies saved (dnxd.prev, dnx.prev)"

echo
echo "=== installing v0.2 ==="
sudo install -m 0755 /tmp/dnxd /usr/local/bin/dnxd
sudo install -m 0755 /tmp/dnx  /usr/local/bin/dnx
sudo systemctl restart dnxd
sleep 4

echo
echo "=== service ==="
sudo systemctl is-active dnxd

echo
echo "=== identity AFTER upgrade (hash must match the one above) ==="
sudo sha256sum /root/.dnx/identity.json 2>/dev/null || echo "  missing!"

echo
echo "=== startup log ==="
sudo journalctl -u dnxd -n 8 --no-pager | tail -8
