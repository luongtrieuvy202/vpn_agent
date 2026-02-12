package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vpnplatform/agent/config"
	"github.com/vpnplatform/agent/trafficcontrol"
	"github.com/vpnplatform/agent/wireguard"
)

func main() {
	log.Printf("[Agent] Starting VPN Agent...")
	
	// Load configuration (API_KEY can be empty if using self-registration)
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("[Agent] Failed to load config: %v", err)
	}
	log.Printf("[Agent] Configuration loaded: BackendURL=%s, WGInterface=%s, Port=%s", 
		cfg.BackendURL, cfg.WireGuardInterface, cfg.ServerPort)

	// Initialize WireGuard manager
	log.Printf("[Agent] Initializing WireGuard manager for interface: %s", cfg.WireGuardInterface)
	wgManager, err := wireguard.NewManager(cfg.WireGuardInterface)
	if err != nil {
		log.Fatalf("[Agent] Failed to initialize WireGuard manager: %v", err)
	}
	defer wgManager.Close()
	log.Printf("[Agent] WireGuard manager initialized successfully")

	// Self-register with backend if we have no ServerID yet (saves server_id + api_key for next start)
	if cfg.ServerID == "" && cfg.BackendURL != "" && cfg.RegistrationSecret != "" {
		log.Printf("[Agent] No ServerID found, attempting self-registration with backend...")
		log.Printf("[Agent] Registration details: BackendURL=%s, RegistrationSecret=%s", 
			cfg.BackendURL, func() string {
				if cfg.RegistrationSecret != "" {
					return "***SET***"
				}
				return "NOT SET"
			}())
		if err := registerWithBackend(cfg, wgManager); err != nil {
			log.Fatalf("[Agent] Self-registration failed: %v", err)
		}
		log.Printf("[Agent] Successfully registered with backend: server_id=%s, api_key=%s", 
			cfg.ServerID, func() string {
				if cfg.APIKey != "" {
					return cfg.APIKey[:8] + "..." // Show first 8 chars only
				}
				return "NOT SET"
			}())
	} else if cfg.ServerID != "" {
		log.Printf("[Agent] Using existing registration: server_id=%s", cfg.ServerID)
	} else {
		log.Printf("[Agent] No registration configured - BackendURL=%v, RegistrationSecret=%v", 
			cfg.BackendURL != "", cfg.RegistrationSecret != "")
	}

	// Initialize Traffic Control manager
	log.Printf("[Agent] Initializing Traffic Control manager (enabled=%v, capacity=%d Mbps)...", 
		cfg.TrafficControlEnabled, cfg.TotalCapacityMbps)
	tcManager, err := trafficcontrol.NewManager(cfg.WireGuardInterface, cfg.IFBInterface)
	if err != nil {
		log.Fatalf("[Agent] Failed to initialize Traffic Control manager: %v", err)
	}
	log.Printf("[Agent] Traffic Control manager initialized successfully")

	// Set Gin mode
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	log.Printf("[Agent] HTTP router initialized")

	// API Key middleware
	apiKeyMiddleware := func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" || apiKey != cfg.APIKey {
			log.Printf("[API] Unauthorized request from %s: %s %s (missing or invalid API key)", 
				c.ClientIP(), c.Request.Method, c.Request.URL.Path)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid API key"})
			c.Abort()
			return
		}
		log.Printf("[API] Authenticated request: %s %s from %s", 
			c.Request.Method, c.Request.URL.Path, c.ClientIP())
		c.Next()
	}

	// Health check
	r.GET("/health", func(c *gin.Context) {
		log.Printf("[Health] Health check requested from %s", c.ClientIP())
		exists := wgManager.InterfaceExists()
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"wireguard": gin.H{
				"interface_exists": exists,
				"interface_up":     exists,
			},
		})
	})

	// API v1 routes
	api := r.Group("/api/v1")
	api.Use(apiKeyMiddleware)
	{
		// Peer management
		api.POST("/peers", func(c *gin.Context) {
			var req struct {
				PublicKey  string `json:"public_key" binding:"required"`
				AssignedIP string `json:"assigned_ip" binding:"required"`
				AllowedIPs string `json:"allowed_ips"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				log.Printf("[Peer] Failed to parse add peer request: %v", err)
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			log.Printf("[Peer] Adding peer: PublicKey=%s, AssignedIP=%s", 
				req.PublicKey[:16]+"...", req.AssignedIP)

			// Parse IP
			ipNet, err := parseCIDR(req.AssignedIP)
			if err != nil {
				log.Printf("[Peer] Invalid assigned_ip: %s", req.AssignedIP)
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid assigned_ip"})
				return
			}

			// Add peer
			if err := wgManager.AddPeer(req.PublicKey, []net.IPNet{*ipNet}); err != nil {
				log.Printf("[Peer] ERROR: Failed to add peer: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			log.Printf("[Peer] Successfully added peer: PublicKey=%s, AssignedIP=%s", 
				req.PublicKey[:16]+"...", req.AssignedIP)
			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"peer": gin.H{
					"public_key":  req.PublicKey,
					"assigned_ip": req.AssignedIP,
					"transfer": gin.H{
						"received": 0,
						"sent":     0,
					},
				},
			})
		})

		api.DELETE("/peers/:public_key", func(c *gin.Context) {
			publicKey := c.Param("public_key")
			if err := wgManager.RemovePeer(publicKey); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"success": true,
			})
		})

		api.GET("/peers/:public_key/stats", func(c *gin.Context) {
			publicKey := c.Param("public_key")
			peer, err := wgManager.GetPeer(publicKey)
			if err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "peer not found"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"public_key":     peer.PublicKey.String(),
				"bytes_received": peer.ReceiveBytes,
				"bytes_sent":     peer.TransmitBytes,
				"last_handshake": peer.LastHandshakeTime,
			})
		})

		api.GET("/peers", func(c *gin.Context) {
			peers, err := wgManager.ListPeers()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			result := make([]gin.H, 0)
			for _, peer := range peers {
				allowedIPs := make([]string, 0)
				for _, ip := range peer.AllowedIPs {
					allowedIPs = append(allowedIPs, ip.String())
				}

				result = append(result, gin.H{
					"public_key":    peer.PublicKey.String(),
					"allowed_ips":   allowedIPs,
					"transfer": gin.H{
						"received": peer.ReceiveBytes,
						"sent":     peer.TransmitBytes,
					},
					"last_handshake": peer.LastHandshakeTime,
				})
			}

			c.JSON(http.StatusOK, gin.H{
				"peers": result,
				"total": len(result),
			})
		})

		// Traffic Control
		api.POST("/traffic-control", func(c *gin.Context) {
			var req struct {
				PeerIP        string `json:"peer_ip" binding:"required"`
				SpeedLimitMbps int   `json:"speed_limit_mbps" binding:"required"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			if err := tcManager.ApplyLimit(req.PeerIP, req.SpeedLimitMbps); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			rule := tcManager.ListRules()[req.PeerIP]
			c.JSON(http.StatusOK, gin.H{
				"success":         true,
				"peer_ip":         req.PeerIP,
				"speed_limit_mbps": req.SpeedLimitMbps,
				"class_id":        rule.ClassID,
			})
		})

		api.DELETE("/traffic-control/:peer_ip", func(c *gin.Context) {
			peerIP := c.Param("peer_ip")
			if err := tcManager.RemoveLimit(peerIP); err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"success": true,
			})
		})
	}

	// Start usage push to backend when backend cannot reach this agent (e.g. behind NAT)
	if cfg.BackendURL != "" && cfg.ServerID != "" {
		log.Printf("[Agent] Starting usage pusher (BackendURL=%s, ServerID=%s)", 
			cfg.BackendURL, cfg.ServerID)
		go runUsagePusher(cfg, wgManager)
	} else {
		log.Printf("[Agent] Usage pusher disabled (BackendURL=%v, ServerID=%v)", 
			cfg.BackendURL != "", cfg.ServerID != "")
	}

	// Start server with graceful shutdown
	addr := cfg.ServerHost + ":" + cfg.ServerPort
	log.Printf("[Agent] VPN Agent starting HTTP server on %s", addr)
	log.Printf("[Agent] Server ready to accept connections")

	// Create HTTP server with timeout settings
	srv := &http.Server{
		Addr:    addr,
		Handler: r,
	}

	// Start server in a goroutine
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[Agent] Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	log.Printf("[Agent] Received signal: %v, initiating graceful shutdown...", sig)

	// Unregister from backend before shutting down
	if cfg.ServerID != "" && cfg.APIKey != "" && cfg.BackendURL != "" {
		log.Printf("[Agent] Unregistering from backend...")
		if err := unregisterFromBackend(cfg); err != nil {
			log.Printf("[Agent] WARNING: Failed to unregister from backend: %v", err)
		} else {
			log.Printf("[Agent] Successfully unregistered from backend")
		}
	}

	// Give server 5 seconds to finish handling requests
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("[Agent] Server forced to shutdown: %v", err)
	} else {
		log.Printf("[Agent] Server gracefully stopped")
	}
}

func runUsagePusher(cfg *config.Config, wgManager *wireguard.Manager) {
	log.Printf("[UsagePusher] Starting usage pusher (interval: 30s)")
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		log.Printf("[UsagePusher] Collecting peer usage statistics...")
		peers, err := wgManager.ListPeers()
		if err != nil {
			log.Printf("[UsagePusher] ERROR: Failed to list peers: %v", err)
			continue
		}
		log.Printf("[UsagePusher] Found %d active peers", len(peers))
		payload := struct {
			ServerID string `json:"server_id"`
			APIKey   string `json:"api_key"`
			Peers    []struct {
				PublicKey     string `json:"public_key"`
				BytesReceived int64  `json:"bytes_received"`
				BytesSent     int64  `json:"bytes_sent"`
			} `json:"peers"`
		}{
			ServerID: cfg.ServerID,
			APIKey:   cfg.APIKey,
			Peers:    make([]struct {
				PublicKey     string `json:"public_key"`
				BytesReceived int64  `json:"bytes_received"`
				BytesSent     int64  `json:"bytes_sent"`
			}, 0, len(peers)),
		}
		for _, p := range peers {
			payload.Peers = append(payload.Peers, struct {
				PublicKey     string `json:"public_key"`
				BytesReceived int64  `json:"bytes_received"`
				BytesSent     int64  `json:"bytes_sent"`
			}{
				PublicKey:     p.PublicKey.String(),
				BytesReceived: p.ReceiveBytes,
				BytesSent:     p.TransmitBytes,
			})
		}
		if len(payload.Peers) == 0 {
			continue
		}
		body, _ := json.Marshal(payload)
		url := strings.TrimSuffix(cfg.BackendURL, "/") + "/api/v1/agents/usage/report"
		log.Printf("[UsagePusher] Sending usage report to: %s (peers: %d)", url, len(payload.Peers))
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			log.Printf("[UsagePusher] ERROR: Failed to create request: %v", err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("[UsagePusher] ERROR: Failed to send usage report: %v", err)
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			log.Printf("[UsagePusher] WARNING: Backend returned status %d", resp.StatusCode)
		} else {
			log.Printf("[UsagePusher] Successfully sent usage report for %d peers", len(payload.Peers))
		}
	}
}

func parseCIDR(cidr string) (*net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return ipNet, nil
}

func registerWithBackend(cfg *config.Config, wgManager *wireguard.Manager) error {
	log.Printf("[Registration] Starting registration process...")
	
	// Get WireGuard device info
	log.Printf("[Registration] Getting WireGuard device information...")
	publicKey, listenPort, err := wgManager.DeviceInfo()
	if err != nil {
		log.Printf("[Registration] ERROR: Failed to get WireGuard device info: %v", err)
		return fmt.Errorf("failed to get WireGuard device info: %w", err)
	}
	log.Printf("[Registration] WireGuard info: PublicKey=%s, ListenPort=%d", publicKey, listenPort)
	
	subnet := cfg.SubnetCIDR
	if subnet == "" {
		subnet = "10.0.0.0/24"
		log.Printf("[Registration] Using default subnet: %s", subnet)
	} else {
		log.Printf("[Registration] Using configured subnet: %s", subnet)
	}
	
	// Prepare registration request
	body := struct {
		RegistrationSecret string `json:"registration_secret"`
		PublicKey          string `json:"public_key"`
		WireguardPort      int    `json:"wireguard_port"`
		SubnetCIDR         string `json:"subnet_cidr"`
	}{
		RegistrationSecret: cfg.RegistrationSecret,
		PublicKey:           publicKey,
		WireguardPort:       listenPort,
		SubnetCIDR:          subnet,
	}
	
	raw, err := json.Marshal(body)
	if err != nil {
		log.Printf("[Registration] ERROR: Failed to marshal registration request: %v", err)
		return fmt.Errorf("failed to marshal request: %w", err)
	}
	
	url := strings.TrimSuffix(cfg.BackendURL, "/") + "/api/v1/agents/register"
	log.Printf("[Registration] Sending registration request to: %s", url)
	log.Printf("[Registration] Request payload: PublicKey=%s, WireguardPort=%d, SubnetCIDR=%s", 
		publicKey, listenPort, subnet)
	
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		log.Printf("[Registration] ERROR: Failed to create HTTP request: %v", err)
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	
	// Send request
	log.Printf("[Registration] Sending POST request to backend...")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("[Registration] ERROR: Failed to send request to backend: %v", err)
		log.Printf("[Registration] Check if backend is reachable at: %s", cfg.BackendURL)
		return fmt.Errorf("failed to connect to backend: %w", err)
	}
	defer resp.Body.Close()
	
	log.Printf("[Registration] Backend responded with status: %d", resp.StatusCode)
	
	if resp.StatusCode != http.StatusCreated {
		var errBody struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		if errBody.Error != "" {
			log.Printf("[Registration] ERROR: Backend returned error: %s", errBody.Error)
			return fmt.Errorf("backend returned %d: %s", resp.StatusCode, errBody.Error)
		}
		log.Printf("[Registration] ERROR: Backend returned status %d (no error message)", resp.StatusCode)
		return fmt.Errorf("backend returned %d", resp.StatusCode)
	}
	
	log.Printf("[Registration] Registration successful! Parsing response...")
	var result struct {
		ServerID   string `json:"server_id"`
		AgentAPIKey string `json:"agent_api_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("[Registration] ERROR: Failed to decode response: %v", err)
		return fmt.Errorf("failed to decode response: %w", err)
	}
	
	if result.ServerID == "" || result.AgentAPIKey == "" {
		log.Printf("[Registration] ERROR: Backend response missing required fields: ServerID=%v, AgentAPIKey=%v", 
			result.ServerID != "", result.AgentAPIKey != "")
		return fmt.Errorf("backend did not return server_id and agent_api_key")
	}
	
	log.Printf("[Registration] Received: ServerID=%s, AgentAPIKey=%s...", 
		result.ServerID, func() string {
			if len(result.AgentAPIKey) > 8 {
				return result.AgentAPIKey[:8]
			}
			return result.AgentAPIKey
		}())
	
	log.Printf("[Registration] Saving registration state to disk...")
	if err := config.SaveRegistrationState(result.ServerID, result.AgentAPIKey); err != nil {
		log.Printf("[Registration] ERROR: Failed to save registration state: %v", err)
		return fmt.Errorf("saving registration state: %w", err)
	}
	log.Printf("[Registration] Registration state saved successfully")
	
	cfg.ServerID = result.ServerID
	cfg.APIKey = result.AgentAPIKey
	
	log.Printf("[Registration] Registration completed successfully!")
	return nil
}

func unregisterFromBackend(cfg *config.Config) error {
	if cfg.BackendURL == "" || cfg.ServerID == "" || cfg.APIKey == "" {
		return fmt.Errorf("missing required configuration for unregistration")
	}

	log.Printf("[Unregister] Unregistering server from backend...")
	log.Printf("[Unregister] ServerID: %s, BackendURL: %s", cfg.ServerID, cfg.BackendURL)

	body := struct {
		ServerID string `json:"server_id"`
		APIKey   string `json:"api_key"`
	}{
		ServerID: cfg.ServerID,
		APIKey:   cfg.APIKey,
	}

	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	url := strings.TrimSuffix(cfg.BackendURL, "/") + "/api/v1/agents/unregister"
	log.Printf("[Unregister] Sending unregister request to: %s", url)

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Use a short timeout for unregistration
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to backend: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errBody struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		if errBody.Error != "" {
			return fmt.Errorf("backend returned %d: %s", resp.StatusCode, errBody.Error)
		}
		return fmt.Errorf("backend returned %d", resp.StatusCode)
	}

	log.Printf("[Unregister] Successfully unregistered from backend")
	return nil
}
