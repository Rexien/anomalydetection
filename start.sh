#!/bin/bash
# ── HNG Stage 3 — Startup Script ──────────────────────────────
# Handles Podman's broken CNI networking by:
#   1. Creating the CNI network config
#   2. Starting nextcloud first to get its IP
#   3. Updating nginx config with the real IP
#   4. Starting nginx and detector

set -e

cd "$(dirname "$0")"

echo "=== HNG Anomaly Detection — Starting ==="

# Clean up
echo "[1/6] Cleaning up old containers..."
sudo docker-compose down 2>/dev/null || true
sudo podman rm -af 2>/dev/null || true

# Create CNI network config (Podman bug workaround)
echo "[2/6] Creating CNI network config..."
sudo tee /etc/cni/net.d/hng-stage3_default.conflist > /dev/null << 'CNIEOF'
{"cniVersion":"0.4.0","name":"hng-stage3_default","plugins":[{"type":"bridge","bridge":"cni-podman1","isGateway":true,"ipMasq":true,"hairpinMode":true,"ipam":{"type":"host-local","routes":[{"dst":"0.0.0.0/0"}],"ranges":[[{"subnet":"10.89.0.0/16","gateway":"10.89.0.1"}]]}},{"type":"portmap","capabilities":{"portMappings":true}},{"type":"firewall"},{"type":"tuning"}]}
CNIEOF

# Inject Slack webhook if placeholder exists
echo "[3/6] Checking config..."
if [ -n "$SLACK_WEBHOOK_URL" ]; then
    sed -i "s|YOUR_SLACK_WEBHOOK_URL_HERE|${SLACK_WEBHOOK_URL}|g" detector/config.yaml 2>/dev/null || true
fi

# Start nextcloud first to discover its IP
echo "[4/6] Starting nextcloud..."
sudo docker-compose up -d nextcloud
sleep 5

# Get nextcloud container IP
NC_IP=$(sudo podman inspect nextcloud --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || echo "")
if [ -z "$NC_IP" ]; then
    NC_IP=$(sudo podman inspect nextcloud --format '{{.NetworkSettings.IPAddress}}' 2>/dev/null || echo "10.89.0.2")
fi
echo "    Nextcloud IP: $NC_IP"

# Update nginx config with the real IP
echo "[5/6] Updating nginx upstream to $NC_IP..."
sed -i "s|server [0-9.]*:80;|server ${NC_IP}:80;|g" nginx/nginx.conf

# Start everything
echo "[6/6] Starting all services..."
sudo docker-compose up -d --build
sleep 3

echo ""
echo "=== All services started! ==="
echo "  Nextcloud: http://$(curl -s ifconfig.me)"
echo "  Dashboard: http://$(curl -s ifconfig.me):8080"
echo ""
echo "View logs:  sudo docker-compose logs -f detector"
