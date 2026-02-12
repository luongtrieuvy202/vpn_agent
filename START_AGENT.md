# How to Start the VPN Agent

## Prerequisites

- **Linux system** (Ubuntu/Debian recommended)
- **WireGuard installed** and configured
- **Root/sudo access** (required for WireGuard operations)
- **Go 1.21+** (if building from source)
- **Backend URL** and **Registration Secret** (for auto-registration)

## Quick Start

### Method 1: Build and Run Directly

1. **Navigate to agent directory:**
   ```bash
   cd agent
   ```

2. **Install dependencies:**
   ```bash
   go mod download
   ```

3. **Create `.env` file:**
   ```bash
   cat > .env << EOF
   # Backend Configuration
   BACKEND_URL=http://your-backend-url:8080
   REGISTRATION_SECRET=your-secret-key-here
   
   # Server Configuration (optional - will be set after registration)
   SERVER_ID=
   API_KEY=
   
   # WireGuard Configuration
   WG_INTERFACE=wg0
   SUBNET_CIDR=10.0.0.0/24
   
   # Agent API Configuration
   PORT=8080
   HOST=0.0.0.0
   
   # Traffic Control
   TC_ENABLED=true
   TC_TOTAL_CAPACITY_MBPS=10000
   IFB_INTERFACE=ifb0
   
   # Logging
   LOG_LEVEL=info
   EOF
   ```

4. **Build the agent:**
   ```bash
   go build -o vpn-agent ./cmd/agent
   ```

5. **Run the agent (requires root):**
   ```bash
   sudo ./vpn-agent
   ```

   The agent will:
   - Auto-register with the backend if `BACKEND_URL` and `REGISTRATION_SECRET` are set
   - Save `SERVER_ID` and `API_KEY` to disk for future starts
   - Start listening on port 8080

### Method 2: Using Docker

1. **Build the Docker image:**
   ```bash
   cd agent
   docker build -t vpn-agent .
   ```

2. **Run with environment variables:**
   ```bash
   docker run -d \
     --name vpn-agent \
     --network host \
     --cap-add=NET_ADMIN \
     --cap-add=SYS_MODULE \
     -e BACKEND_URL=http://your-backend-url:8080 \
     -e REGISTRATION_SECRET=your-secret-key \
     -e WG_INTERFACE=wg0 \
     -e PORT=8080 \
     -v /etc/wireguard:/etc/wireguard \
     vpn-agent
   ```

   **Note:** Docker requires `--network host` and capabilities for WireGuard to work properly.

### Method 3: Systemd Service (Production)

1. **Build the agent:**
   ```bash
   cd agent
   go build -o vpn-agent ./cmd/agent
   ```

2. **Install to system directory:**
   ```bash
   sudo mkdir -p /opt/vpn-agent
   sudo cp vpn-agent /opt/vpn-agent/
   sudo cp .env /opt/vpn-agent/
   sudo chmod +x /opt/vpn-agent/vpn-agent
   ```

3. **Create systemd service:**
   ```bash
   sudo tee /etc/systemd/system/vpn-agent.service > /dev/null << EOF
   [Unit]
   Description=VPN Node Agent
   After=network.target wireguard.service
   Requires=wireguard.service
   
   [Service]
   Type=simple
   User=root
   WorkingDirectory=/opt/vpn-agent
   ExecStart=/opt/vpn-agent/vpn-agent
   Restart=always
   RestartSec=5
   EnvironmentFile=/opt/vpn-agent/.env
   
   [Install]
   WantedBy=multi-user.target
   EOF
   ```

4. **Enable and start:**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable vpn-agent
   sudo systemctl start vpn-agent
   ```

5. **Check status:**
   ```bash
   sudo systemctl status vpn-agent
   sudo journalctl -u vpn-agent -f
   ```

## Configuration Options

### Required for Auto-Registration

- `BACKEND_URL` - Your backend API URL (e.g., `http://api.example.com:8080`)
- `REGISTRATION_SECRET` - Secret key shared with backend (must match `REGISTRATION_SECRET` in backend `.env`)

### Optional (Set after registration)

- `SERVER_ID` - UUID of this server (auto-set after registration)
- `API_KEY` - API key for backend communication (auto-set after registration)

### WireGuard Settings

- `WG_INTERFACE` - WireGuard interface name (default: `wg0`)
- `SUBNET_CIDR` - Subnet for IP allocation (default: `10.0.0.0/24`)

### Agent API Settings

- `PORT` - Agent API port (default: `8080`)
- `HOST` - Bind address (default: `0.0.0.0`)

### Traffic Control

- `TC_ENABLED` - Enable bandwidth limiting (default: `true`)
- `TC_TOTAL_CAPACITY_MBPS` - Total server capacity in Mbps (default: `10000`)
- `IFB_INTERFACE` - Intermediate Functional Block interface (default: `ifb0`)

## Verification

### Check if agent is running:

```bash
# Health check (no auth required)
curl http://localhost:8080/health

# Should return:
# {"status":"healthy","wireguard":{"interface_exists":true,"interface_up":true}}
```

### Check registration:

```bash
# Check logs for registration message
sudo journalctl -u vpn-agent | grep "Registered with backend"

# Or if running directly:
sudo ./vpn-agent
# Look for: "Registered with backend: server_id=xxx-xxx-xxx"
```

### Check backend sees the server:

```bash
# From backend machine or via API
curl http://your-backend-url:8080/api/v1/servers
```

## Troubleshooting

### Agent fails to start

**Error: "Failed to initialize WireGuard manager"**
- Ensure WireGuard is installed: `sudo apt install wireguard`
- Check WireGuard interface exists: `sudo wg show`
- Create interface if needed: `sudo wg-quick up wg0`

**Error: "Self-registration failed"**
- Check `BACKEND_URL` is correct and reachable
- Verify `REGISTRATION_SECRET` matches backend
- Check backend logs for registration attempts
- Ensure backend has `REGISTRATION_SECRET` set

**Error: "Failed to initialize Traffic Control manager"**
- Ensure `tc` is available: `which tc`
- Install if needed: `sudo apt install iproute2`
- Can disable with `TC_ENABLED=false` in `.env`

### Agent not registering

1. **Check connectivity:**
   ```bash
   curl http://your-backend-url:8080/health
   ```

2. **Check registration secret:**
   - Must match exactly between agent and backend
   - No extra spaces or quotes

3. **Check backend logs:**
   ```bash
   docker logs vpn-backend | grep register
   ```

### Agent registered but not showing as available

1. **Check server status in database:**
   ```sql
   SELECT server_id, name, status, agent_url, agent_api_key 
   FROM servers 
   WHERE server_id = 'your-server-id';
   ```

2. **Verify agent URL is correct:**
   - Should be accessible from backend
   - Format: `http://your-server-ip:8080`

3. **Test agent health from backend:**
   ```bash
   curl http://your-agent-ip:8080/health
   ```

## Next Steps

After the agent starts successfully:

1. **Verify registration** - Check backend sees the server
2. **Test VPN connection** - Try connecting via frontend
3. **Monitor logs** - Watch for any errors
4. **Set up monitoring** - Configure alerts if needed

## Security Notes

- **Firewall:** Only allow backend IPs to access agent port 8080
- **HTTPS:** Use reverse proxy (Nginx/Traefik) for HTTPS in production
- **API Keys:** Rotate regularly
- **Logs:** Monitor for unauthorized access attempts
