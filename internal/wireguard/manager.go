package wireguard

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"example.com/Web-VPN/internal/config"
	"example.com/Web-VPN/internal/database"
	"example.com/Web-VPN/internal/models"
	"gopkg.in/ini.v1"
)

type Manager struct {
	ConfigPath string
	Interface  string
	AppConfig  *config.Config
	DB         *database.DB
}

func NewManager(cfg *config.Config, db *database.DB) *Manager {

	return &Manager{
		ConfigPath: cfg.WgConfigPath,
		Interface:  cfg.WgInterface,
		AppConfig:  cfg,
		DB:         db,
	}
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

// ... (Keep GetStatus and GetPeers from Phase 1, but update GetPeers to include PrivateKey) ...
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

		disabled := false
		if section.HasKey("Disabled") {
			disabled, _ = section.Key("Disabled").Bool()
		}

		peers = append(peers, models.Peer{
			Name:       section.Name(),
			PublicKey:  section.Key("PublicKey").String(),
			PrivateKey: section.Key("PrivateKey").String(),
			AllowedIPs: section.Key("AllowedIPs").String(),
			Disabled:   disabled,
		})
	}
	return peers, nil
}

// GetPeerStats parses `wg show <iface> dump` for live stats
func (m *Manager) GetPeerStats(peers []models.Peer) (map[string]models.PeerStats, error) {
	cmd := exec.Command("wg", "show", m.Interface, "dump")
	out, err := cmd.Output()
	if err != nil {
		return nil, err // Interface might be down
	}

	stats := make(map[string]models.PeerStats)
	pubKeyToName := make(map[string]string)
	for _, p := range peers {
		pubKeyToName[p.PublicKey] = p.Name
	}

	lines := strings.Split(string(out), "\n")
	for i := 1; i < len(lines); i++ { // Skip first line (interface info)
		parts := strings.Split(lines[i], "\t")
		if len(parts) < 8 {
			continue
		}

		pubKey := parts[0]
		name := pubKeyToName[pubKey]
		if name == "" {
			continue
		}

		var handshakeTime time.Time
		if parts[4] != "0" {
			ts, _ := strconv.ParseInt(parts[4], 10, 64)
			handshakeTime = time.Unix(ts, 0)
		}

		rx, _ := strconv.ParseInt(parts[5], 10, 64)
		tx, _ := strconv.ParseInt(parts[6], 10, 64)

		stats[name] = models.PeerStats{
			Endpoint:        parts[2],
			AllowedIPs:      parts[3],
			LatestHandshake: handshakeTime,
			TransferRX:      rx,
			TransferTX:      tx,
		}
	}
	return stats, nil
}

// Update AddPeer to use DB for IP
func (m *Manager) AddPeer(name string) error {
	// 1. Get next IP from DB
	ip, err := m.DB.GetNextIP()
	if err != nil {
		return err
	}
	allowedIP := ip + "/32"

	// 2. Generate Keys (same as before)
	privKeyCmd := exec.Command("wg", "genkey")
	privKeyBytes, _ := privKeyCmd.Output()
	privKey := strings.TrimSpace(string(privKeyBytes))

	pubKeyCmd := exec.Command("wg", "pubkey")
	pubKeyCmd.Stdin = strings.NewReader(privKey)
	pubKeyBytes, _ := pubKeyCmd.Output()
	pubKey := strings.TrimSpace(string(pubKeyBytes))

	// 3. Save to DB
	if err := m.DB.AddPeer(name, ip); err != nil {
		return fmt.Errorf("DB error: %w", err)
	}

	// 4. Update Config File (same as before)
	cfg, _ := ini.Load(m.ConfigPath)
	if cfg == nil {
		cfg = ini.Empty()
	}

	section, _ := cfg.NewSection(name)
	section.Key("PublicKey").SetValue(pubKey)
	section.Key("PrivateKey").SetValue(privKey)
	section.Key("AllowedIPs").SetValue(allowedIP)

	cfg.SaveTo(m.ConfigPath)
	exec.Command("wg", "syncconf", m.Interface, m.ConfigPath).Run()
	return nil
}

// DeletePeer removes from config and running interface
func (m *Manager) DeletePeer(name string) error {
	cfg, err := ini.Load(m.ConfigPath)
	if err != nil {
		return err
	}

	// Get public key before deleting to remove from running interface
	section := cfg.Section(name)
	if section == nil {
		return fmt.Errorf("peer not found")
	}
	pubKey := section.Key("PublicKey").String()

	cfg.DeleteSection(name)
	if err := cfg.SaveTo(m.ConfigPath); err != nil {
		return err
	}

	// Remove from running interface
	exec.Command("wg", "set", m.Interface, "peer", pubKey, "remove").Run()
	m.DB.DeletePeer(name)
	return nil
}

func (m *Manager) TogglePeer(name string) error {
	cfg, err := ini.Load(m.ConfigPath)
	if err != nil {
		return err
	}

	section := cfg.Section(name)
	if section == nil {
		return fmt.Errorf("peer not found")
	}

	// Flip the state
	currentState, _ := section.Key("Disabled").Bool()
	section.Key("Disabled").SetValue(strconv.FormatBool(!currentState))

	if err := cfg.SaveTo(m.ConfigPath); err != nil {
		return err
	}

	// Sync the interface.
	// Note: wg syncconf will add missing peers and remove peers that are no longer in the config.
	// Since we keep the peer in the config but just mark it disabled, we need to manually
	// remove it from the running interface if it was just disabled.
	if !currentState { // It was enabled, now it's disabled
		pubKey := section.Key("PublicKey").String()
		exec.Command("wg", "set", m.Interface, "peer", pubKey, "remove").Run()
	} else { // It was disabled, now it's enabled. syncconf will add it back.
		exec.Command("wg", "syncconf", m.Interface, m.ConfigPath).Run()
	}

	return nil
}

// GenerateClientConfig creates the .conf string for the client
func (m *Manager) GenerateClientConfig(peerName string) (string, error) {
	peers, _ := m.GetPeers()
	var targetPeer *models.Peer
	for i := range peers {
		if peers[i].Name == peerName {
			targetPeer = &peers[i]
			break
		}
	}
	if targetPeer == nil || targetPeer.PrivateKey == "" {
		return "", fmt.Errorf("peer not found or missing private key")
	}

	// --- FIX: Robust Server Public Key Retrieval ---
	var serverPubKey string

	// 1. Try to get it from the running interface
	cmd := exec.Command("wg", "show", m.Interface, "public-key")
	serverPubKeyBytes, err := cmd.Output()
	if err == nil {
		serverPubKey = strings.TrimSpace(string(serverPubKeyBytes))
	}

	// 2. Fallback: If interface is down, derive it from the PrivateKey in the config file
	if serverPubKey == "" {
		cfg, err := ini.Load(m.ConfigPath)
		if err == nil {
			serverPrivKey := cfg.Section("Interface").Key("PrivateKey").String()
			if serverPrivKey != "" {
				pubKeyCmd := exec.Command("wg", "pubkey")
				pubKeyCmd.Stdin = strings.NewReader(serverPrivKey)
				pubKeyOut, err := pubKeyCmd.Output()
				if err == nil {
					serverPubKey = strings.TrimSpace(string(pubKeyOut))
				}
			}
		}
	}

	// 3. Final check
	if serverPubKey == "" {
		return "", fmt.Errorf("could not determine server public key. Ensure wg0.conf has a valid PrivateKey in the [Interface] section")
	}
	// -----------------------------------------------

	// Ensure Endpoint and DNS are not empty
	endpoint := m.AppConfig.ServerEndpoint
	if endpoint == "" || strings.Contains(endpoint, "YOUR_SERVER") {
		return "", fmt.Errorf("please update ServerEndpoint in internal/config/config.go with your actual public IP")
	}

	configStr := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
DNS = %s

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`, targetPeer.PrivateKey, targetPeer.AllowedIPs, m.AppConfig.DNS, serverPubKey, endpoint)

	return configStr, nil
}
