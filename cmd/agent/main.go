package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vpnplatform/agent/config"
	"github.com/vpnplatform/agent/trafficcontrol"
	"github.com/vpnplatform/agent/wireguard"
)

func main() {
	// Load configuration (API_KEY can be empty if using self-registration)
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize WireGuard manager
	wgManager, err := wireguard.NewManager(cfg.WireGuardInterface)
	if err != nil {
		log.Fatalf("Failed to initialize WireGuard manager: %v", err)
	}
	defer wgManager.Close()

	// Self-register with backend if we have no ServerID yet (saves server_id + api_key for next start)
	if cfg.ServerID == "" && cfg.BackendURL != "" && cfg.RegistrationSecret != "" {
		if err := registerWithBackend(cfg, wgManager); err != nil {
			log.Fatalf("Self-registration failed: %v", err)
		}
		log.Printf("Registered with backend: server_id=%s", cfg.ServerID)
	}

	// Initialize Traffic Control manager
	tcManager, err := trafficcontrol.NewManager(cfg.WireGuardInterface, cfg.IFBInterface)
	if err != nil {
		log.Fatalf("Failed to initialize Traffic Control manager: %v", err)
	}

	// Set Gin mode
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// API Key middleware
	apiKeyMiddleware := func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" || apiKey != cfg.APIKey {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid API key"})
			c.Abort()
			return
		}
		c.Next()
	}

	// Health check
	r.GET("/health", func(c *gin.Context) {
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
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			// Parse IP
			ipNet, err := parseCIDR(req.AssignedIP)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid assigned_ip"})
				return
			}

			// Add peer
			if err := wgManager.AddPeer(req.PublicKey, []net.IPNet{*ipNet}); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

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
		go runUsagePusher(cfg, wgManager)
	}

	// Start server
	addr := cfg.ServerHost + ":" + cfg.ServerPort
	log.Printf("VPN Agent starting on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
		os.Exit(1)
	}
}

func runUsagePusher(cfg *config.Config, wgManager *wireguard.Manager) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		peers, err := wgManager.ListPeers()
		if err != nil {
			log.Printf("[Usage push] ListPeers: %v", err)
			continue
		}
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
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("[Usage push] POST %s: %v", url, err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			log.Printf("[Usage push] POST %s: status %d", url, resp.StatusCode)
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
	publicKey, listenPort, err := wgManager.DeviceInfo()
	if err != nil {
		return err
	}
	subnet := cfg.SubnetCIDR
	if subnet == "" {
		subnet = "10.0.0.0/24"
	}
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
	raw, _ := json.Marshal(body)
	url := strings.TrimSuffix(cfg.BackendURL, "/") + "/api/v1/agents/register"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		var errBody struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		if errBody.Error != "" {
			return fmt.Errorf("backend returned %d: %s", resp.StatusCode, errBody.Error)
		}
		return fmt.Errorf("backend returned %d", resp.StatusCode)
	}
	var result struct {
		ServerID   string `json:"server_id"`
		AgentAPIKey string `json:"agent_api_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	if result.ServerID == "" || result.AgentAPIKey == "" {
		return fmt.Errorf("backend did not return server_id and agent_api_key")
	}
	if err := config.SaveRegistrationState(result.ServerID, result.AgentAPIKey); err != nil {
		return fmt.Errorf("saving registration state: %w", err)
	}
	cfg.ServerID = result.ServerID
	cfg.APIKey = result.AgentAPIKey
	return nil
}
