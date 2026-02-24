package license

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
)

func NewKey() (string, error) {
	// 20 bytes => 32 base32 chars (no padding)
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	s := enc.EncodeToString(b)
	s = strings.ToUpper(s)
	// group by 4 chars for readability
	var parts []string
	for i := 0; i < len(s); i += 4 {
		end := i + 4
		if end > len(s) {
			end = len(s)
		}
		parts = append(parts, s[i:end])
	}
	return "KYPAQET-" + strings.Join(parts, "-"), nil
}
