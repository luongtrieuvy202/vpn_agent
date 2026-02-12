package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	// Server
	ServerPort string
	ServerHost string

	// WireGuard
	WireGuardInterface string
	SubnetCIDR         string

	// Traffic Control
	TrafficControlEnabled bool
	TotalCapacityMbps     int
	IFBInterface         string

	// API Key (used for incoming backend requests and for pushing usage to backend)
	APIKey string

	// Usage push to backend (when backend cannot reach this agent, e.g. behind NAT)
	BackendURL string // e.g. https://api.example.com
	ServerID   string // UUID of this server in the platform (set by dashboard or auto-registration)

	// Agent self-registration: set with BACKEND_URL to have agent register and get ServerID + APIKey automatically
	RegistrationSecret string

	// Logging
	LogLevel string
	LogFile  string
}

func Load() (*Config, error) {
	// Get current working directory for logging
	wd, _ := os.Getwd()
	log.Printf("[Config] Current working directory: %s", wd)
	
	// Try loading .env from common locations
	envPaths := []string{
		"/etc/vpn-agent/.env",  // Systemd service location
		".env",                  // Current directory
		"../.env",               // Parent directory
	}
	
	envLoaded := false
	for _, path := range envPaths {
		if err := godotenv.Load(path); err == nil {
			log.Printf("[Config] Successfully loaded .env file from: %s", path)
			envLoaded = true
			break // Successfully loaded
		} else {
			log.Printf("[Config] Failed to load .env from %s: %v", path, err)
		}
	}
	
	if !envLoaded {
		log.Printf("[Config] No .env file found in any of the checked locations")
		log.Printf("[Config] Will use environment variables if set, or defaults")
	}
	// Continue even if .env not found - environment variables might be set by systemd

	config := &Config{
		ServerPort:            getEnv("PORT", "8080"),
		ServerHost:            getEnv("HOST", "0.0.0.0"),
		WireGuardInterface:    getEnv("WG_INTERFACE", "wg0"),
		SubnetCIDR:            getEnv("SUBNET_CIDR", "10.0.0.0/24"),
		TrafficControlEnabled: getEnvAsBool("TC_ENABLED", true),
		TotalCapacityMbps:     getEnvAsInt("TC_TOTAL_CAPACITY_MBPS", 10000),
		IFBInterface:          getEnv("IFB_INTERFACE", "ifb0"),
		APIKey:                getEnv("API_KEY", ""),
		BackendURL:            getEnv("BACKEND_URL", ""),
		ServerID:              getEnv("SERVER_ID", ""),
		RegistrationSecret:   getEnv("REGISTRATION_SECRET", ""),
		LogLevel:              getEnv("LOG_LEVEL", "info"),
		LogFile:               getEnv("LOG_FILE", ""),
	}

	// Load persisted registration (server_id + api_key) if present
	loadRegistrationState(config)

	// Log loaded configuration (sensitive values masked)
	log.Printf("[Config] Loaded configuration:")
	log.Printf("[Config]   BackendURL: %s", func() string {
		if config.BackendURL != "" {
			return config.BackendURL
		}
		return "(not set)"
	}())
	log.Printf("[Config]   RegistrationSecret: %s", func() string {
		if config.RegistrationSecret != "" {
			return "***SET***"
		}
		return "(not set)"
	}())
	log.Printf("[Config]   ServerID: %s", func() string {
		if config.ServerID != "" {
			return config.ServerID
		}
		return "(not set)"
	}())
	log.Printf("[Config]   APIKey: %s", func() string {
		if config.APIKey != "" {
			return config.APIKey[:min(8, len(config.APIKey))] + "..."
		}
		return "(not set)"
	}())
	log.Printf("[Config]   WGInterface: %s", config.WireGuardInterface)
	log.Printf("[Config]   Port: %s", config.ServerPort)

	// Either we have API_KEY (and optionally SERVER_ID), or we will self-register
	if config.APIKey == "" && (config.RegistrationSecret == "" || config.BackendURL == "") {
		return nil, fmt.Errorf("API_KEY must be set, or set BACKEND_URL and REGISTRATION_SECRET for self-registration")
	}

	return config, nil
}

// registrationStatePath is where we persist server_id and api_key after self-registration.
func registrationStatePath() string {
	if p := os.Getenv("REGISTRATION_STATE_FILE"); p != "" {
		return strings.TrimSpace(p)
	}
	for _, base := range []string{"/etc/vpn-agent", "."} {
		if _, err := os.Stat(base); err == nil {
			return base + "/registration.json"
		}
	}
	return "registration.json"
}

type registrationState struct {
	ServerID string `json:"server_id"`
	APIKey   string `json:"api_key"`
}

func loadRegistrationState(c *Config) {
	path := registrationStatePath()
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var state registrationState
	if err := json.Unmarshal(data, &state); err != nil {
		return
	}
	if state.ServerID != "" {
		c.ServerID = strings.TrimSpace(state.ServerID)
	}
	if state.APIKey != "" {
		c.APIKey = strings.TrimSpace(state.APIKey)
	}
}

// SaveRegistrationState persists server_id and api_key after self-registration so the next start has them.
func SaveRegistrationState(serverID, apiKey string) error {
	path := registrationStatePath()
	data, err := json.Marshal(registrationState{ServerID: serverID, APIKey: apiKey})
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		// Trim whitespace to prevent issues with .env file formatting
		return strings.TrimSpace(value)
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var result int
		if _, err := fmt.Sscanf(value, "%d", &result); err == nil {
			return result
		}
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return value == "true" || value == "1" || value == "yes"
	}
	return defaultValue
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
