package wireguard

import (
	"fmt"
	"net"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Manager struct {
	interfaceName string
	client        *wgctrl.Client
}

func NewManager(interfaceName string) (*Manager, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create wgctrl client: %w", err)
	}

	return &Manager{
		interfaceName: interfaceName,
		client:        client,
	}, nil
}

func (m *Manager) AddPeer(publicKey string, allowedIPs []net.IPNet) error {
	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	peer := wgtypes.PeerConfig{
		PublicKey:  key,
		AllowedIPs: allowedIPs,
	}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peer},
	}

	if err := m.client.ConfigureDevice(m.interfaceName, config); err != nil {
		return fmt.Errorf("failed to configure device: %w", err)
	}

	return nil
}

func (m *Manager) RemovePeer(publicKey string) error {
	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	peer := wgtypes.PeerConfig{
		PublicKey: key,
		Remove:    true,
	}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peer},
	}

	if err := m.client.ConfigureDevice(m.interfaceName, config); err != nil {
		return fmt.Errorf("failed to remove peer: %w", err)
	}

	return nil
}

func (m *Manager) ListPeers() ([]wgtypes.Peer, error) {
	device, err := m.client.Device(m.interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	return device.Peers, nil
}

func (m *Manager) GetPeer(publicKey string) (*wgtypes.Peer, error) {
	peers, err := m.ListPeers()
	if err != nil {
		return nil, err
	}

	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	for _, peer := range peers {
		if peer.PublicKey == key {
			return &peer, nil
		}
	}

	return nil, fmt.Errorf("peer not found")
}

func (m *Manager) Close() error {
	if m.client != nil {
		return m.client.Close()
	}
	return nil
}

// Check if interface exists
func (m *Manager) InterfaceExists() bool {
	_, err := m.client.Device(m.interfaceName)
	return err == nil
}
