package config

type Config struct {
	Port         string // Web server port
	WgConfigPath string // Path to wg0.conf
	WgInterface  string // e.g., wg0
}

func Load() *Config {
	return &Config{
		Port:         ":8080",
		WgConfigPath: "/etc/wireguard/wg0.conf", // Change for local dev
		WgInterface:  "wg0",
	}
}