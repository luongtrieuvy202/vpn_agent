#!/bin/bash

###############################################################################
# Ubuntu VPN Server Setup Script
# 
# This script automates the setup of an Ubuntu server as a VPN node for the
# VPN management platform.
#
# Usage: sudo ./setup_ubuntu_vpn_server.sh
#
# Requirements:
# - Ubuntu 20.04 or higher
# - Root or sudo access
# - Internet connection
###############################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Get script directory (where this script is located)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Find agent repository root (directory containing go.mod)
# This works whether the repo is named vpn_agent, agent, or anything else
find_repo_root() {
    local dir="$SCRIPT_DIR"
    while [ "$dir" != "/" ]; do
        if [ -f "$dir/go.mod" ]; then
            echo "$dir"
            return 0
        fi
        dir="$(dirname "$dir")"
    done
    # If not found, fall back to script directory
    echo "$SCRIPT_DIR"
}

AGENT_SOURCE_DIR="$(find_repo_root)"

# Configuration variables
WG_INTERFACE="wg0"
WG_PORT="51820"
AGENT_PORT="8080"
SUBNET_CIDR="10.0.0.0/24"
SERVER_IP="10.0.0.1"
AGENT_DIR="/opt/vpn-agent"      # Installation directory for built agent
AGENT_CONFIG_DIR="/etc/vpn-agent"
WG_DIR="/etc/wireguard"

# Functions
print_header() {
    echo -e "\n${CYAN}========================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}========================================${NC}\n"
}

print_step() {
    echo -e "\n${BLUE}[STEP]${NC} $1\n"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_info() {
    echo -e "${CYAN}ℹ${NC} $1"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        print_error "Please run as root or with sudo"
        exit 1
    fi
}

# Get user input
get_input() {
    local prompt="$1"
    local default="$2"
    local var_name="$3"
    
    if [ -n "$default" ]; then
        read -p "$(echo -e ${CYAN}$prompt${NC} [${YELLOW}$default${NC}]): " input
        eval "$var_name=\"\${input:-$default}\""
    else
        read -p "$(echo -e ${CYAN}$prompt${NC}): " input
        eval "$var_name=\"$input\""
    fi
}

# Detect network interface
detect_network_interface() {
    local interface=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [ -z "$interface" ]; then
        interface="eth0"
    fi
    echo "$interface"
}

###############################################################################
# Main Setup Process
###############################################################################

main() {
    print_header "Ubuntu VPN Server Setup"
    
    echo -e "This script will:"
    echo -e "  1. Install required packages (WireGuard, Go, etc.)"
    echo -e "  2. Configure WireGuard"
    echo -e "  3. Install and configure VPN Agent"
    echo -e "  4. Set up systemd services"
    echo -e "  5. Configure firewall"
    echo -e ""
    
    read -p "$(echo -e ${YELLOW}Continue? [y/N]${NC}): " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        print_info "Setup cancelled"
        exit 0
    fi
    
    # Collect information
    print_header "Collecting Information"
    
    get_input "Server public IP address" "" SERVER_PUBLIC_IP
    get_input "Region (e.g., us-east, eu-west)" "us-east" REGION
    get_input "Server name" "Ubuntu VPN Server" SERVER_NAME
    get_input "Backend API IP (for firewall)" "" BACKEND_IP
    get_input "Max peers" "100" MAX_PEERS
    get_input "Subnet CIDR" "$SUBNET_CIDR" SUBNET_CIDR
    
    # Detect network interface
    NET_INTERFACE=$(detect_network_interface)
    print_info "Detected network interface: $NET_INTERFACE"
    get_input "Network interface for NAT" "$NET_INTERFACE" NET_INTERFACE
    
    # Step 1: Update system
    print_header "Step 1: Updating System"
    print_step "Updating package list..."
    apt update -qq
    print_success "Package list updated"
    
    print_step "Upgrading system packages..."
    apt upgrade -y -qq
    print_success "System upgraded"
    
    # Step 2: Install dependencies
    print_header "Step 2: Installing Dependencies"
    print_step "Installing WireGuard and tools..."
    apt install -y wireguard wireguard-tools iptables iproute2 curl wget ufw > /dev/null 2>&1
    print_success "WireGuard installed"
    
    print_step "Installing Go..."
    if ! command -v go &> /dev/null; then
        GO_VERSION="1.21.5"
        GO_ARCH="amd64"
        wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -O /tmp/go.tar.gz
        tar -C /usr/local -xzf /tmp/go.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
        rm /tmp/go.tar.gz
        print_success "Go ${GO_VERSION} installed"
    else
        print_info "Go already installed: $(go version)"
    fi
    
    # Step 3: Enable IP forwarding
    print_header "Step 3: Configuring Network"
    print_step "Enabling IP forwarding..."
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    sysctl -p > /dev/null
    print_success "IP forwarding enabled"
    
    # Step 4: Set up WireGuard
    print_header "Step 4: Setting Up WireGuard"
    
    print_step "Generating WireGuard keys..."
    mkdir -p "$WG_DIR"
    cd "$WG_DIR"
    
    if [ ! -f privatekey ]; then
        wg genkey | tee privatekey | wg pubkey > publickey
        chmod 600 privatekey
        chmod 644 publickey
        print_success "WireGuard keys generated"
    else
        print_warning "WireGuard keys already exist, skipping generation"
    fi
    
    WG_PRIVATE_KEY=$(cat privatekey)
    WG_PUBLIC_KEY=$(cat publickey)
    
    print_info "WireGuard Public Key: $WG_PUBLIC_KEY"
    echo "$WG_PUBLIC_KEY" > /tmp/wg_public_key.txt
    print_info "Public key saved to /tmp/wg_public_key.txt"
    
    # Create WireGuard configuration
    print_step "Creating WireGuard configuration..."
    cat > "${WG_DIR}/${WG_INTERFACE}.conf" <<EOF
[Interface]
PrivateKey = $WG_PRIVATE_KEY
ListenPort = $WG_PORT
Address = $SERVER_IP/24

# Post-up: Enable NAT and forwarding
PostUp = iptables -A FORWARD -i $WG_INTERFACE -j ACCEPT; iptables -A FORWARD -o $WG_INTERFACE -j ACCEPT; iptables -t nat -A POSTROUTING -o $NET_INTERFACE -j MASQUERADE

# Post-down: Clean up rules
PostDown = iptables -D FORWARD -i $WG_INTERFACE -j ACCEPT; iptables -D FORWARD -o $WG_INTERFACE -j ACCEPT; iptables -t nat -D POSTROUTING -o $NET_INTERFACE -j MASQUERADE
EOF
    
    chmod 600 "${WG_DIR}/${WG_INTERFACE}.conf"
    print_success "WireGuard configuration created"
    
    # Start WireGuard
    print_step "Starting WireGuard..."
    systemctl enable wg-quick@${WG_INTERFACE} > /dev/null 2>&1
    systemctl start wg-quick@${WG_INTERFACE}
    sleep 2
    
    if systemctl is-active --quiet wg-quick@${WG_INTERFACE}; then
        print_success "WireGuard started"
    else
        print_error "Failed to start WireGuard"
        systemctl status wg-quick@${WG_INTERFACE}
        exit 1
    fi
    
    # Step 5: Set up VPN Agent
    print_header "Step 5: Setting Up VPN Agent"
    
    # Verify agent source code exists (find repo root by looking for go.mod)
    print_step "Locating agent source code..."
    print_info "Script location: $SCRIPT_DIR"
    
    # Re-detect repo root in case script was moved
    AGENT_SOURCE_DIR="$(find_repo_root)"
    
    if [ ! -f "$AGENT_SOURCE_DIR/go.mod" ]; then
        print_error "Agent repository not found (go.mod missing)"
        print_error "Searched from: $SCRIPT_DIR"
        print_error "Expected go.mod at: $AGENT_SOURCE_DIR/go.mod"
        print_info "This script should be run from within the vpn_agent repository."
        print_info "The repository can be cloned as: git clone <repo-url> vpn_agent"
        exit 1
    fi
    
    print_success "Agent repository found at: $AGENT_SOURCE_DIR"
    if [ "$AGENT_SOURCE_DIR" != "$SCRIPT_DIR" ]; then
        print_info "Script is in subdirectory, using repository root"
    fi
    
    # Create installation directory
    mkdir -p "$AGENT_DIR"
    
    # Build agent from source directory
    print_step "Building VPN agent..."
    cd "$AGENT_SOURCE_DIR"
    
    if [ ! -f "go.mod" ]; then
        print_error "go.mod not found in $AGENT_SOURCE_DIR"
        exit 1
    fi
    
    go mod download
    go build -o "$AGENT_DIR/vpn-agent" ./cmd/agent
    
    if [ -f "$AGENT_DIR/vpn-agent" ]; then
        print_success "VPN agent built successfully"
    else
        print_error "Failed to build VPN agent"
        exit 1
    fi
    
    # Generate API key
    print_step "Generating agent API key..."
    AGENT_API_KEY=$(openssl rand -hex 32)
    echo "$AGENT_API_KEY" > /tmp/agent_api_key.txt
    print_info "Agent API Key: $AGENT_API_KEY"
    print_info "API key saved to /tmp/agent_api_key.txt"
    
    # Create agent configuration
    print_step "Creating agent configuration..."
    mkdir -p "$AGENT_CONFIG_DIR"
    
    cat > "${AGENT_CONFIG_DIR}/.env" <<EOF
# Agent API Key
API_KEY=$AGENT_API_KEY

# WireGuard interface
WG_INTERFACE=$WG_INTERFACE

# Agent server settings
PORT=$AGENT_PORT
HOST=0.0.0.0

# Traffic control settings
TC_ENABLED=true
TC_TOTAL_CAPACITY_MBPS=10000
EOF
    
    chmod 600 "${AGENT_CONFIG_DIR}/.env"
    print_success "Agent configuration created"
    
    # Create systemd service
    print_step "Creating systemd service..."
    cat > /etc/systemd/system/vpn-agent.service <<EOF
[Unit]
Description=VPN Node Agent
After=network.target wireguard.service
Requires=wg-quick@${WG_INTERFACE}.service

[Service]
Type=simple
User=root
WorkingDirectory=$AGENT_DIR
ExecStart=$AGENT_DIR/vpn-agent
Restart=always
RestartSec=5
EnvironmentFile=${AGENT_CONFIG_DIR}/.env

# Security settings
NoNewPrivileges=false
PrivateTmp=true

# Logging
StandardOutput=append:/var/log/vpn-agent/agent.log
StandardError=append:/var/log/vpn-agent/agent-error.log

[Install]
WantedBy=multi-user.target
EOF
    
    # Create log directory
    mkdir -p /var/log/vpn-agent
    
    systemctl daemon-reload
    systemctl enable vpn-agent > /dev/null 2>&1
    print_success "Systemd service created"
    
    # Step 6: Configure firewall (never lock out SSH or block agent)
    print_header "Step 6: Configuring Firewall"
    
    print_step "Configuring UFW firewall..."
    
    # Set explicit defaults so behavior is predictable (deny incoming, allow outgoing)
    ufw default deny incoming > /dev/null 2>&1
    ufw default allow outgoing > /dev/null 2>&1
    
    # 1) Always allow SSH first - never enable UFW without this (avoids lockout)
    ufw allow 22/tcp comment 'SSH' > /dev/null 2>&1
    print_success "SSH (22/tcp) allowed"
    
    # 2) WireGuard
    ufw allow ${WG_PORT}/udp comment 'WireGuard' > /dev/null 2>&1
    print_success "WireGuard (${WG_PORT}/udp) allowed"
    
    # 3) Agent API: from backend IP only, or from anywhere if not set (backend must reach agent)
    if [ -n "$BACKEND_IP" ]; then
        ufw allow from "$BACKEND_IP" to any port ${AGENT_PORT} comment 'VPN Agent API' > /dev/null 2>&1
        print_success "Agent API (${AGENT_PORT}/tcp) allowed from $BACKEND_IP only"
    else
        ufw allow ${AGENT_PORT}/tcp comment 'VPN Agent API' > /dev/null 2>&1
        print_success "Agent API (${AGENT_PORT}/tcp) allowed (restrict later with: ufw allow from <backend-ip> to any port $AGENT_PORT)"
    fi
    
    # Safety: confirm before enabling so user sees what is allowed
    echo ""
    echo -e "${CYAN}UFW will be enabled with these incoming rules:${NC}"
    echo -e "  • SSH (22/tcp)"
    echo -e "  • WireGuard (${WG_PORT}/udp)"
    echo -e "  • Agent API (${AGENT_PORT}/tcp)"
    echo ""
    read -p "$(echo -e ${YELLOW}Enable UFW now? [Y/n]${NC}): " ufw_confirm
    if [[ "$ufw_confirm" =~ ^[Nn]$ ]]; then
        print_warning "UFW not enabled. Enable manually when ready: sudo ufw enable"
    else
        ufw --force enable > /dev/null 2>&1
        print_success "Firewall enabled"
    fi
    print_info "Verify anytime with: sudo ufw status"
    
    # Step 7: Start services
    print_header "Step 7: Starting Services"
    
    print_step "Starting VPN agent..."
    systemctl start vpn-agent
    sleep 2
    
    if systemctl is-active --quiet vpn-agent; then
        print_success "VPN agent started"
    else
        print_error "Failed to start VPN agent"
        systemctl status vpn-agent
        exit 1
    fi
    
    # Step 8: Verify setup
    print_header "Step 8: Verifying Setup"
    
    print_step "Checking WireGuard..."
    if wg show "$WG_INTERFACE" > /dev/null 2>&1; then
        print_success "WireGuard is running"
        wg show "$WG_INTERFACE"
    else
        print_error "WireGuard is not running"
    fi
    
    print_step "Checking VPN agent..."
    if curl -f http://localhost:${AGENT_PORT}/health > /dev/null 2>&1; then
        print_success "VPN agent is responding"
        curl -s http://localhost:${AGENT_PORT}/health | python3 -m json.tool 2>/dev/null || curl -s http://localhost:${AGENT_PORT}/health
    else
        print_error "VPN agent is not responding"
        print_info "Check logs: journalctl -u vpn-agent -n 50"
    fi
    
    # Step 9: Generate database SQL
    print_header "Step 9: Database Registration"
    
    print_step "Generating database registration SQL..."
    
    SQL_FILE="/tmp/register_server.sql"
    cat > "$SQL_FILE" <<EOF
-- Register VPN Server in Database
-- Run this SQL in your PostgreSQL database

INSERT INTO servers (
    name,
    region,
    public_ip,
    wireguard_port,
    public_key,
    endpoint,
    subnet_cidr,
    max_peers,
    status,
    agent_url,
    agent_api_key
) VALUES (
    '$SERVER_NAME',
    '$REGION',
    '$SERVER_PUBLIC_IP',
    $WG_PORT,
    '$WG_PUBLIC_KEY',
    '$SERVER_PUBLIC_IP:$WG_PORT',
    '$SUBNET_CIDR',
    $MAX_PEERS,
    'active',
    'http://$SERVER_PUBLIC_IP:$AGENT_PORT',
    '$AGENT_API_KEY'
)
RETURNING server_id;

-- After inserting, get the server_id and run:
-- (Replace SERVER_ID with the actual UUID returned above)

-- Initialize IP pool
INSERT INTO ip_allocations (server_id, assigned_ip, status)
SELECT 
    'SERVER_ID_HERE'::uuid,
    ('10.0.0.' || generate_series(2, 254)::text)::inet,
    'free'
ON CONFLICT DO NOTHING;

-- Verify
SELECT 
    server_id,
    name,
    region,
    status,
    current_peers,
    max_peers
FROM servers 
WHERE name = '$SERVER_NAME';
EOF
    
    print_success "SQL script generated: $SQL_FILE"
    print_info "Copy this file to your database server and execute it"
    
    # Create summary
    print_header "Setup Complete!"
    
    echo -e "${GREEN}✓${NC} WireGuard configured and running"
    echo -e "${GREEN}✓${NC} VPN agent installed and running"
    echo -e "${GREEN}✓${NC} Firewall configured"
    echo -e "${GREEN}✓${NC} Systemd services enabled"
    echo ""
    echo -e "${CYAN}Important Information:${NC}"
    echo -e "  ${YELLOW}WireGuard Public Key:${NC} $WG_PUBLIC_KEY"
    echo -e "  ${YELLOW}Agent API Key:${NC} $AGENT_API_KEY"
    echo -e "  ${YELLOW}Agent URL:${NC} http://$SERVER_PUBLIC_IP:$AGENT_PORT"
    echo -e "  ${YELLOW}Server Public IP:${NC} $SERVER_PUBLIC_IP"
    echo -e "  ${YELLOW}Region:${NC} $REGION"
    echo ""
    echo -e "${CYAN}Files Created:${NC}"
    echo -e "  • WireGuard config: ${WG_DIR}/${WG_INTERFACE}.conf"
    echo -e "  • Agent config: ${AGENT_CONFIG_DIR}/.env"
    echo -e "  • Public key: /tmp/wg_public_key.txt"
    echo -e "  • API key: /tmp/agent_api_key.txt"
    echo -e "  • SQL script: $SQL_FILE"
    echo ""
    echo -e "${CYAN}Next Steps:${NC}"
    echo -e "  1. Copy $SQL_FILE to your database server"
    echo -e "  2. Execute the SQL to register the server"
    echo -e "  3. Initialize the IP pool (see SQL script)"
    echo -e "  4. Test connection from backend"
    echo ""
    echo -e "${CYAN}Useful Commands:${NC}"
    echo -e "  • Check WireGuard: ${YELLOW}wg show $WG_INTERFACE${NC}"
    echo -e "  • Check agent: ${YELLOW}systemctl status vpn-agent${NC}"
    echo -e "  • View agent logs: ${YELLOW}journalctl -u vpn-agent -f${NC}"
    echo -e "  • Test agent API: ${YELLOW}curl http://localhost:$AGENT_PORT/health${NC}"
    echo ""
    echo -e "${GREEN}Setup completed successfully!${NC}\n"
}

# Run main function
check_root
main
