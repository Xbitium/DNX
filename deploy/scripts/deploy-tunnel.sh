#!/usr/bin/env bash
# Install the tunnel-allowlist build of dnxd.
#
# Usage:  bash deploy-tunnel.sh            # install, publish nothing
#         bash deploy-tunnel.sh 22         # install and publish port 22
#
# The allowlist replaces the old --allow-tunnel boolean. A node with no
# --tunnel-ports refuses every inbound tunnel, so upgrading without an
# argument is safe and changes no exposure.
set -e
PORTS="${1:-}"

test -f /tmp/dnxd || { echo "FATAL: /tmp/dnxd missing"; exit 1; }
test -f /tmp/dnx  || { echo "FATAL: /tmp/dnx missing";  exit 1; }
chmod +x /tmp/dnxd /tmp/dnx

echo "=== identity BEFORE (must be unchanged after) ==="
sudo sha256sum /root/.dnx/identity.json

sudo cp -f /usr/local/bin/dnxd /usr/local/bin/dnxd.prev 2>/dev/null || true
sudo cp -f /usr/local/bin/dnx  /usr/local/bin/dnx.prev  2>/dev/null || true
sudo install -m 0755 /tmp/dnxd /usr/local/bin/dnxd
sudo install -m 0755 /tmp/dnx  /usr/local/bin/dnx

UNIT=/etc/systemd/system/dnxd.service
# Drop any previous allowlist so re-running is idempotent.
sudo sed -i 's| --tunnel-ports [0-9,]*||' "$UNIT"
if [ -n "$PORTS" ]; then
  sudo sed -i "s|\(ExecStart=/usr/local/bin/dnxd .*\)$|\1 --tunnel-ports $PORTS|" "$UNIT"
  echo "unit now publishes ports: $PORTS"
else
  echo "unit publishes no ports (inbound tunnels refused)"
fi

echo
echo "=== ExecStart ==="
grep ExecStart "$UNIT"

sudo systemctl daemon-reload
sudo systemctl restart dnxd
sleep 4

echo
echo "=== service ==="
sudo systemctl is-active dnxd

echo
echo "=== identity AFTER (hash must match above) ==="
sudo sha256sum /root/.dnx/identity.json

echo
echo "=== startup log ==="
sudo journalctl -u dnxd -n 6 --no-pager | tail -6
