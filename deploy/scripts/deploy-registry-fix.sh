#!/usr/bin/env bash
# Deploy the ownership-fix registry to dnxroute1 (142.93.177.59).
#
# What changes:
#   - a name->key binding is no longer deleted after 10 minutes of silence
#   - bindings persist to /var/lib/dnx/registry.json and survive a restart
#   - endpoints still expire after 60s, because that is liveness, not ownership
set -e

NEW=/tmp/dnx-registry
INSTALLED=/usr/local/bin/dnx-registry
BACKUP=/usr/local/bin/dnx-registry.prev

test -f "$NEW" || { echo "FATAL: $NEW not found"; exit 1; }
chmod +x "$NEW"

echo "=== current state before touching anything ==="
sudo systemctl is-active dnx-registry || true
sudo journalctl -u dnx-registry -n 3 --no-pager | tail -3 || true

# Keep the running binary so a rollback is one command.
if [ -f "$INSTALLED" ]; then
  sudo cp -f "$INSTALLED" "$BACKUP"
  echo "rollback copy saved to $BACKUP"
fi

echo
echo "=== installing ==="
sudo install -m 0755 "$NEW" "$INSTALLED"
sudo mkdir -p /var/lib/dnx
sudo chmod 0700 /var/lib/dnx

sudo systemctl restart dnx-registry
sleep 3

echo
echo "=== service ==="
sudo systemctl is-active dnx-registry

echo
echo "=== startup log (expect a 'restored N binding(s)' line) ==="
sudo journalctl -u dnx-registry -n 12 --no-pager | tail -12

echo
echo "=== waiting 20s for live nodes to re-register ==="
sleep 20
sudo journalctl -u dnx-registry -n 20 --no-pager | grep -E "NEW name bound|restored" | tail -6 || echo "(no registrations seen yet)"

echo
echo "=== persisted ownership file ==="
if sudo test -f /var/lib/dnx/registry.json; then
  echo "names now persisted:"
  sudo grep '"name"' /var/lib/dnx/registry.json || true
else
  echo "NOTE: state file not created yet — it is written on the first new claim"
fi
