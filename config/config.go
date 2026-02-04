package config

import (
	"fmt"
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

	// API Key
	APIKey string

	// Logging
	LogLevel string
	LogFile  string
}

func Load() (*Config, error) {
	_ = godotenv.Load()

	config := &Config{
		ServerPort:           getEnv("PORT", "8080"),
		ServerHost:           getEnv("HOST", "0.0.0.0"),
		WireGuardInterface:   getEnv("WG_INTERFACE", "wg0"),
		SubnetCIDR:           getEnv("SUBNET_CIDR", "10.0.0.0/24"),
		TrafficControlEnabled: getEnvAsBool("TC_ENABLED", true),
		TotalCapacityMbps:     getEnvAsInt("TC_TOTAL_CAPACITY_MBPS", 10000),
		IFBInterface:         getEnv("IFB_INTERFACE", "ifb0"),
		APIKey:               getEnv("API_KEY", ""),
		LogLevel:             getEnv("LOG_LEVEL", "info"),
		LogFile:              getEnv("LOG_FILE", ""),
	}

	if config.APIKey == "" {
		return nil, fmt.Errorf("API_KEY must be set")
	}

	return config, nil
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
