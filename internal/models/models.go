package models

type ServerStatus struct {
	IsRunning   bool
	ListenPort  int
	Address     string
	PublicKey   string
	TotalPeers  int
	ActivePeers int
}

type Peer struct {
	Name        string
	PublicKey   string
	PrivateKey  string // Only stored temporarily or in a secure DB later
	AllowedIPs  string
	Endpoint    string
	LatestHandshake string
}