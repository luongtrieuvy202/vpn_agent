package trafficcontrol

import (
	"fmt"
	"os/exec"
	"sync"
)

type Manager struct {
	interfaceName string
	ifbInterface string
	nextClassID  int
	mu           sync.Mutex
	rules        map[string]*TCRule
}

type TCRule struct {
	ClassID      string
	PeerIP       string
	SpeedLimitMbps int
	Direction    string
}

func NewManager(interfaceName, ifbInterface string) (*Manager, error) {
	m := &Manager{
		interfaceName: interfaceName,
		ifbInterface: ifbInterface,
		nextClassID:  10, // Start from 1:10
		rules:        make(map[string]*TCRule),
	}

	// Initialize root qdisc if not exists
	if err := m.initializeRootQdisc(); err != nil {
		return nil, fmt.Errorf("failed to initialize root qdisc: %w", err)
	}

	return m, nil
}

func (m *Manager) initializeRootQdisc() error {
	// Check if root qdisc exists
	cmd := exec.Command("tc", "qdisc", "show", "dev", m.interfaceName)
	if err := cmd.Run(); err == nil {
		// Qdisc exists, check if it's HTB
		output, _ := cmd.Output()
		if contains(string(output), "htb") {
			return nil // Already initialized
		}
	}

	// Create root qdisc
	cmd = exec.Command("tc", "qdisc", "add", "dev", m.interfaceName, "root", "handle", "1:", "htb", "default", "30")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create root qdisc: %w", err)
	}

	// Create root class (10 Gbps default)
	cmd = exec.Command("tc", "class", "add", "dev", m.interfaceName, "parent", "1:", "classid", "1:1", "htb", "rate", "10000mbit")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create root class: %w", err)
	}

	return nil
}

func (m *Manager) ApplyLimit(peerIP string, speedLimitMbps int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// If rule already exists, remove it first (idempotent operation)
	if _, exists := m.rules[peerIP]; exists {
		// Remove existing rule before applying new one
		rule := m.rules[peerIP]
		
		// Remove filter
		cmd := exec.Command("tc", "filter", "del",
			"dev", m.interfaceName,
			"protocol", "ip",
			"parent", "1:0",
			"prio", "1",
			"u32", "match", "ip", "dst", peerIP+"/32",
			"flowid", rule.ClassID)
		_ = cmd.Run() // Ignore error if filter doesn't exist

		// Remove class
		cmd = exec.Command("tc", "class", "del", "dev", m.interfaceName, "classid", rule.ClassID)
		_ = cmd.Run() // Ignore error if class doesn't exist

		// Remove from map
		delete(m.rules, peerIP)
	}

	// Generate class ID
	classID := fmt.Sprintf("1:%d", m.nextClassID)
	m.nextClassID++

	// Create class
	cmd := exec.Command("tc", "class", "add",
		"dev", m.interfaceName,
		"parent", "1:1",
		"classid", classID,
		"htb", "rate", fmt.Sprintf("%dmbit", speedLimitMbps),
		"ceil", fmt.Sprintf("%dmbit", speedLimitMbps))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create class: %w", err)
	}

	// Add filter for egress (outgoing)
	cmd = exec.Command("tc", "filter", "add",
		"dev", m.interfaceName,
		"protocol", "ip",
		"parent", "1:0",
		"prio", "1",
		"u32", "match", "ip", "dst", peerIP+"/32",
		"flowid", classID)
	if err := cmd.Run(); err != nil {
		// Cleanup class
		exec.Command("tc", "class", "del", "dev", m.interfaceName, "classid", classID).Run()
		return fmt.Errorf("failed to add filter: %w", err)
	}

	// Store rule
	m.rules[peerIP] = &TCRule{
		ClassID:       classID,
		PeerIP:        peerIP,
		SpeedLimitMbps: speedLimitMbps,
		Direction:     "both",
	}

	return nil
}

func (m *Manager) RemoveLimit(peerIP string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rule, exists := m.rules[peerIP]
	if !exists {
		return fmt.Errorf("traffic control rule not found for %s", peerIP)
	}

	// Remove filter
	cmd := exec.Command("tc", "filter", "del",
		"dev", m.interfaceName,
		"protocol", "ip",
		"parent", "1:0",
		"prio", "1",
		"u32", "match", "ip", "dst", peerIP+"/32",
		"flowid", rule.ClassID)
	_ = cmd.Run() // Ignore error if filter doesn't exist

	// Remove class
	cmd = exec.Command("tc", "class", "del", "dev", m.interfaceName, "classid", rule.ClassID)
	if err := cmd.Run(); err != nil {
		// Log but don't fail
		fmt.Printf("Warning: failed to remove class %s: %v\n", rule.ClassID, err)
	}

	// Remove from map
	delete(m.rules, peerIP)

	return nil
}

func (m *Manager) ListRules() map[string]*TCRule {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make(map[string]*TCRule)
	for k, v := range m.rules {
		result[k] = v
	}
	return result
}

func (m *Manager) HasRule(peerIP string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, exists := m.rules[peerIP]
	return exists
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
