# VPN Node Agent

Lightweight daemon that runs on each WireGuard VPN server node to manage peers and traffic control.

## Prerequisites

- Go 1.21 or higher
- WireGuard installed and configured
- Linux system with `tc` (traffic control) available
- Root or sudo access (for WireGuard and tc operations)

## Setup

1. **Install dependencies:**
```bash
go mod download
```

2. **Set up environment variables:**
```bash
cp .env.example .env
# Edit .env with your configuration
# IMPORTANT: Set a strong API_KEY
```

3. **Build and run:**
```bash
# Build
go build -o vpn-agent ./cmd/agent

# Run (requires root for WireGuard operations)
sudo ./vpn-agent
```

## Configuration

### Required
- `API_KEY` - Secret key for authenticating with backend
- `WG_INTERFACE` - WireGuard interface name (default: wg0)

### Optional
- `PORT` - Agent API port (default: 8080)
- `HOST` - Bind address (default: 0.0.0.0)
- `TC_ENABLED` - Enable traffic control (default: true)
- `TC_TOTAL_CAPACITY_MBPS` - Total server capacity (default: 10000)

## API Endpoints

All endpoints require `X-API-Key` header.

### Peer Management
- `POST /api/v1/peers` - Create WireGuard peer
- `DELETE /api/v1/peers/:public_key` - Remove peer
- `GET /api/v1/peers` - List all peers

### Traffic Control
- `POST /api/v1/traffic-control` - Apply bandwidth limit
- `DELETE /api/v1/traffic-control/:peer_ip` - Remove bandwidth limit

### Health
- `GET /health` - Health check (no auth required)

## Systemd Service

Create `/etc/systemd/system/vpn-agent.service`:

```ini
[Unit]
Description=VPN Node Agent
After=network.target wireguard.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/vpn-agent
ExecStart=/opt/vpn-agent/vpn-agent
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable vpn-agent
sudo systemctl start vpn-agent
```

## Security

- Run behind firewall (only allow backend IPs)
- Use HTTPS in production (add reverse proxy)
- Rotate API keys regularly
- Monitor logs for unauthorized access
