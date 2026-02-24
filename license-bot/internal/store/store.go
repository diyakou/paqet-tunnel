package store

import "time"

type License struct {
	Key       string    `json:"key"`
	Limit     int       `json:"limit"`
	Note      string    `json:"note"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

type ServerBinding struct {
	ServerID   string    `json:"server_id"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	SeenCount  int       `json:"seen_count"`
}

type LicenseInfo struct {
	License  License         `json:"license"`
	Used     int             `json:"used"`
	Bindings []ServerBinding `json:"bindings"`
}

type ActivateResult struct {
	OK         bool   `json:"ok"`
	Reason     string `json:"reason"`
	Used       int    `json:"used"`
	Limit      int    `json:"limit"`
	NewlyBound bool   `json:"newly_bound"`
}

type Store interface {
	Close() error

	CreateLicense(limit int, note string) (License, error)
	SetLimit(key string, limit int) (License, error)
	SetEnabled(key string, enabled bool) (License, error)
	GetInfo(key string) (LicenseInfo, error)
	ListLicenses() ([]LicenseInfo, error)

	Activate(key string, serverID string) (ActivateResult, error)
}
