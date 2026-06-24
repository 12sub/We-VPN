package models

import "time"

type ServerStatus struct {
	IsRunning   bool
	ListenPort  int
	Address     string
	PublicKey   string
	TotalPeers  int
}

type Peer struct {
	Name            string
	PublicKey       string
	PrivateKey      string // Stored in config for client generation
	AllowedIPs      string
	Endpoint        string // Live from wg show
	LatestHandshake string // Live from wg show
	TransferRX      int64  // Live from wg show
	TransferTX      int64  // Live from wg show
	Disabled 		bool 
}

type PeerStats struct {
	Endpoint        string
	AllowedIPs      string
	LatestHandshake time.Time
	TransferRX      int64
	TransferTX      int64
}