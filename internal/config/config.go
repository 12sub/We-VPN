package config

import (
	"crypto/rand"
	"encoding/hex"
)

type Config struct {
	Port           string
	WgConfigPath   string
	WgInterface    string
	ServerEndpoint string // e.g., "203.0.113.1:51820" (Your server's public IP)
	DNS            string // e.g., "1.1.1.1"

	// Auth
	AdminUser    string
	AdminPass    string
	SessionToken string // Generated on startup
}

func Load() *Config {
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	return &Config{
		Port:           ":8080",
		WgConfigPath:   "./wg0.conf", // Change to /etc/wireguard/wg0.conf in prod
		WgInterface:    "wg0",
		ServerEndpoint: "172.22.126.52:51820", // <-- UPDATE THIS
		DNS:            "1.1.1.1",

		AdminUser:    "admin",
		AdminPass:    "changeme", // Change this in production!
		SessionToken: hex.EncodeToString(tokenBytes),
	}
}
