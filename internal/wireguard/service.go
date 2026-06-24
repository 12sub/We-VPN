package wireguard

import (
	"fmt"
	"os/exec"
	"strings"
)

// RestartService restarts the wg-quick service
func (m *Manager) RestartService() error {
	cmd := exec.Command("systemctl", "restart", fmt.Sprintf("wg-quick@%s", m.Interface))
	return cmd.Run()
}

func (m *Manager) StopService() error {
	cmd := exec.Command("systemctl", "stop", fmt.Sprintf("wg-quick@%s", m.Interface))
	return cmd.Run()
}

func (m *Manager) StartService() error {
	cmd := exec.Command("systemctl", "start", fmt.Sprintf("wg-quick@%s", m.Interface))
	return cmd.Run()
}

// GetLogs fetches the last 20 lines of the wireguard journal logs
func (m *Manager) GetLogs() (string, error) {
	cmd := exec.Command("journalctl", "-u", fmt.Sprintf("wg-quick@%s", m.Interface), "-n", "20", "--no-pager")
	out, err := cmd.Output()
	if err != nil {
		return "No logs available or journalctl failed.", nil
	}
	return string(out), nil
}

// GetTotalTraffic parses `wg show` to get total server RX/TX for the graph
func (m *Manager) GetTotalTraffic() (int64, int64, error) {
	cmd := exec.Command("wg", "show", m.Interface, "transfer")
	out, err := cmd.Output()
	if err != nil {
		return 0, 0, err
	}

	var totalRX, totalTX int64
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if line == "" { continue }
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			var rx, tx int64
			fmt.Sscanf(parts[1], "%d", &rx)
			fmt.Sscanf(parts[2], "%d", &tx)
			totalRX += rx
			totalTX += tx
		}
	}
	return totalRX, totalTX, nil
}