package database

import (
	"database/sql"
	"fmt"
	_ "modernc.org/sqlite"
)

type DB struct {
	conn *sql.DB
}

func NewDB(dbPath string) (*DB, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	// Create table if not exists
	query := `CREATE TABLE IF NOT EXISTS peers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE NOT NULL,
		ip_address TEXT UNIQUE NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	
	if _, err := conn.Exec(query); err != nil {
		return nil, err
	}

	return &DB{conn: conn}, nil
}

// GetNextIP finds the highest IP and returns the next available one
func (db *DB) GetNextIP() (string, error) {
	var lastIP string
	err := db.conn.QueryRow("SELECT ip_address FROM peers ORDER BY id DESC LIMIT 1").Scan(&lastIP)
	if err == sql.ErrNoRows {
		return "10.0.0.2", nil // Start at .2 (.1 is server)
	}
	if err != nil {
		return "", err
	}

	// Simple parsing for 10.0.0.X
	var a, b, c, d int
	fmt.Sscanf(lastIP, "%d.%d.%d.%d", &a, &b, &c, &d)
	return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d+1), nil
}

func (db *DB) AddPeer(name, ip string) error {
	_, err := db.conn.Exec("INSERT INTO peers (name, ip_address) VALUES (?, ?)", name, ip)
	return err
}

func (db *DB) DeletePeer(name string) error {
	_, err := db.conn.Exec("DELETE FROM peers WHERE name = ?", name)
	return err
}

func (db *DB) GetPeerIP(name string) (string, error) {
	var ip string
	err := db.conn.QueryRow("SELECT ip_address FROM peers WHERE name = ?", name).Scan(&ip)
	return ip, err
}

func (db *DB) Close() {
	db.conn.Close()
}