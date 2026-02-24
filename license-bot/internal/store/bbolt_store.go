package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"kypaqet-license-bot/internal/license"

	"go.etcd.io/bbolt"
)

var (
	errNotFound = errors.New("license not found")
)

const (
	bucketLicenses = "licenses"
	bucketUsage    = "usage"
)

type BBoltStore struct {
	db *bbolt.DB
}

func OpenBBolt(path string) (*BBoltStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, err
	}
	st := &BBoltStore{db: db}
	if err := st.db.Update(func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(bucketLicenses)); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(bucketUsage)); err != nil {
			return err
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return st, nil
}

func (s *BBoltStore) Close() error { return s.db.Close() }

func (s *BBoltStore) CreateLicense(limit int, note string) (License, error) {
	if limit <= 0 {
		return License{}, fmt.Errorf("limit must be > 0")
	}
	key, err := license.NewKey()
	if err != nil {
		return License{}, err
	}
	lic := License{Key: key, Limit: limit, Note: note, Enabled: true, CreatedAt: time.Now().UTC()}
	buf, _ := json.Marshal(lic)

	if err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketLicenses))
		if b.Get([]byte(key)) != nil {
			return fmt.Errorf("key collision, try again")
		}
		if err := b.Put([]byte(key), buf); err != nil {
			return err
		}
		usage := tx.Bucket([]byte(bucketUsage))
		_, err := usage.CreateBucketIfNotExists([]byte(key))
		return err
	}); err != nil {
		return License{}, err
	}
	return lic, nil
}

func (s *BBoltStore) SetLimit(key string, limit int) (License, error) {
	if limit <= 0 {
		return License{}, fmt.Errorf("limit must be > 0")
	}
	var updated License
	if err := s.db.Update(func(tx *bbolt.Tx) error {
		lic, err := getLicense(tx, key)
		if err != nil {
			return err
		}
		lic.Limit = limit
		updated = lic
		return putLicense(tx, lic)
	}); err != nil {
		return License{}, err
	}
	return updated, nil
}

func (s *BBoltStore) SetEnabled(key string, enabled bool) (License, error) {
	var updated License
	if err := s.db.Update(func(tx *bbolt.Tx) error {
		lic, err := getLicense(tx, key)
		if err != nil {
			return err
		}
		lic.Enabled = enabled
		updated = lic
		return putLicense(tx, lic)
	}); err != nil {
		return License{}, err
	}
	return updated, nil
}

func (s *BBoltStore) GetInfo(key string) (LicenseInfo, error) {
	var info LicenseInfo
	if err := s.db.View(func(tx *bbolt.Tx) error {
		lic, err := getLicense(tx, key)
		if err != nil {
			return err
		}
		bindings, err := getBindings(tx, key)
		if err != nil {
			return err
		}
		info = LicenseInfo{License: lic, Used: len(bindings), Bindings: bindings}
		return nil
	}); err != nil {
		return LicenseInfo{}, err
	}
	return info, nil
}

func (s *BBoltStore) ListLicenses() ([]LicenseInfo, error) {
	var out []LicenseInfo
	if err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketLicenses))
		return b.ForEach(func(k, v []byte) error {
			var lic License
			if err := json.Unmarshal(v, &lic); err != nil {
				return err
			}
			bindings, err := getBindings(tx, string(k))
			if err != nil {
				return err
			}
			out = append(out, LicenseInfo{License: lic, Used: len(bindings), Bindings: nil})
			return nil
		})
	}); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].License.CreatedAt.After(out[j].License.CreatedAt)
	})
	return out, nil
}

func (s *BBoltStore) Activate(key string, serverID string) (ActivateResult, error) {
	key = strings.TrimSpace(key)
	serverID = strings.TrimSpace(serverID)
	if key == "" || serverID == "" {
		return ActivateResult{OK: false, Reason: "invalid_request"}, nil
	}
	if len(serverID) > 128 {
		return ActivateResult{OK: false, Reason: "server_id_too_long"}, nil
	}

	var res ActivateResult
	now := time.Now().UTC()
	if err := s.db.Update(func(tx *bbolt.Tx) error {
		lic, err := getLicense(tx, key)
		if err != nil {
			res = ActivateResult{OK: false, Reason: "not_found"}
			return nil
		}
		if !lic.Enabled {
			res = ActivateResult{OK: false, Reason: "disabled", Limit: lic.Limit}
			return nil
		}
		usageRoot := tx.Bucket([]byte(bucketUsage))
		usage := usageRoot.Bucket([]byte(key))
		if usage == nil {
			var err error
			usage, err = usageRoot.CreateBucketIfNotExists([]byte(key))
			if err != nil {
				return err
			}
		}

		existing := usage.Get([]byte(serverID))
		newBinding := false
		var sb ServerBinding
		if existing != nil {
			_ = json.Unmarshal(existing, &sb)
			sb.LastSeen = now
			sb.SeenCount++
		} else {
			used := countKeys(usage)
			if used >= lic.Limit {
				res = ActivateResult{OK: false, Reason: "limit_reached", Used: used, Limit: lic.Limit}
				return nil
			}
			newBinding = true
			sb = ServerBinding{ServerID: serverID, FirstSeen: now, LastSeen: now, SeenCount: 1}
		}
		buf, _ := json.Marshal(sb)
		if err := usage.Put([]byte(serverID), buf); err != nil {
			return err
		}
		used := countKeys(usage)
		res = ActivateResult{OK: true, Reason: "ok", Used: used, Limit: lic.Limit, NewlyBound: newBinding}
		return nil
	}); err != nil {
		return ActivateResult{}, err
	}
	return res, nil
}

func getLicense(tx *bbolt.Tx, key string) (License, error) {
	b := tx.Bucket([]byte(bucketLicenses))
	v := b.Get([]byte(key))
	if v == nil {
		return License{}, errNotFound
	}
	var lic License
	if err := json.Unmarshal(v, &lic); err != nil {
		return License{}, err
	}
	return lic, nil
}

func putLicense(tx *bbolt.Tx, lic License) error {
	b := tx.Bucket([]byte(bucketLicenses))
	buf, _ := json.Marshal(lic)
	return b.Put([]byte(lic.Key), buf)
}

func getBindings(tx *bbolt.Tx, key string) ([]ServerBinding, error) {
	usageRoot := tx.Bucket([]byte(bucketUsage))
	usage := usageRoot.Bucket([]byte(key))
	if usage == nil {
		return nil, nil
	}
	bindings := make([]ServerBinding, 0)
	err := usage.ForEach(func(k, v []byte) error {
		var sb ServerBinding
		if err := json.Unmarshal(v, &sb); err != nil {
			return err
		}
		sb.ServerID = string(k)
		bindings = append(bindings, sb)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(bindings, func(i, j int) bool {
		return bindings[i].LastSeen.After(bindings[j].LastSeen)
	})
	return bindings, nil
}

func countKeys(b *bbolt.Bucket) int {
	// Stats can be stale; iterate for correctness.
	n := 0
	_ = b.ForEach(func(_, _ []byte) error {
		n++
		return nil
	})
	return n
}
