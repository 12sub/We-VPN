package wireguard

import (
	"fmt"
	"os/exec"
	"strings"
	"example.com/Web-VPN/internal/models"
	"gopkg.in/ini.v1"
)

type Manager struct {
	ConfigPath string
	Interface  string
}

func NewManager(configPath, iface string) *Manager {
	return &Manager{ConfigPath: configPath, Interface: iface}
}

// GetStatus checks if the interface is up and gets basic stats
func (m *Manager) GetStatus() (*models.ServerStatus, error) {
	status := &models.ServerStatus{}
	
	// Check if interface is up
	cmd := exec.Command("wg", "show", m.Interface)
	output, err := cmd.Output()
	if err != nil {
		status.IsRunning = false
		return status, nil
	}
	
	status.IsRunning = true
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "listening port:") {
			fmt.Sscanf(line, "listening port: %d", &status.ListenPort)
		}
	}
	
	// Count peers
	peers, _ := m.GetPeers()
	status.TotalPeers = len(peers)
	
	return status, nil
}

// GetPeers reads the config file and returns a list of peers
func (m *Manager) GetPeers() ([]models.Peer, error) {
	cfg, err := ini.Load(m.ConfigPath)
	if err != nil {
		return nil, err
	}

	var peers []models.Peer
	for _, section := range cfg.Sections() {
		if section.Name() == "DEFAULT" || section.Name() == "Interface" {
			continue
		}
		
		peers = append(peers, models.Peer{
			Name:       section.Name(),
			PublicKey:  section.Key("PublicKey").String(),
			AllowedIPs: section.Key("AllowedIPs").String(),
			Endpoint:   section.Key("Endpoint").String(),
		})
	}
	return peers, nil
}

// AddPeer generates keys, updates the config, and reloads WireGuard
func (m *Manager) AddPeer(name string) error {
	// 1. Generate Keys (Requires wg CLI)
	privKeyCmd := exec.Command("wg", "genkey")
	privKeyBytes, err := privKeyCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}
	privKey := strings.TrimSpace(string(privKeyBytes))

	pubKeyCmd := exec.Command("wg", "pubkey")
	pubKeyCmd.Stdin = strings.NewReader(privKey)
	pubKeyBytes, err := pubKeyCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to generate public key: %w", err)
	}
	pubKey := strings.TrimSpace(string(pubKeyBytes))

	// 2. Determine next IP (Simple logic: 10.0.0.x)
	peers, _ := m.GetPeers()
	nextIP := len(peers) + 2 // .1 is server
	allowedIP := fmt.Sprintf("10.0.0.%d/32", nextIP)

	// 3. Update Config File
	cfg, err := ini.Load(m.ConfigPath)
	if err != nil {
		cfg = ini.Empty()
	}

	section, err := cfg.NewSection(name)
	if err != nil {
		return err
	}
	section.Key("PublicKey").SetValue(pubKey)
	section.Key("AllowedIPs").SetValue(allowedIP)

	if err := cfg.SaveTo(m.ConfigPath); err != nil {
		return err
	}

	// 4. Sync config with running interface
	syncCmd := exec.Command("wg", "syncconf", m.Interface, m.ConfigPath)
	if err := syncCmd.Run(); err != nil {
		// If interface isn't running, this will fail, which is fine for now
		fmt.Println("Warning: Could not syncconf. Is WireGuard running?", err)
	}

	return nil
}