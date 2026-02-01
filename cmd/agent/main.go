package main

import (
	"log"
	"net/http"
	"os"

	"net"

	"github.com/gin-gonic/gin"
	"github.com/vpnplatform/agent/config"
	"github.com/vpnplatform/agent/trafficcontrol"
	"github.com/vpnplatform/agent/wireguard"
)

func main() {
	// Load configuration
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

	// Start server
	addr := cfg.ServerHost + ":" + cfg.ServerPort
	log.Printf("VPN Agent starting on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
		os.Exit(1)
	}
}

func parseCIDR(cidr string) (*net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return ipNet, nil
}
