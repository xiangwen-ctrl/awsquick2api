package auth

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"awsquick2api/internal/safefile"
)

// LoadDir reads and decrypts all *.json credential files from authDir using vault.
func LoadDir(authDir string, vault *Vault) ([]*Account, error) {
	if vault == nil {
		return nil, fmt.Errorf("vault is required to load credentials")
	}
	entries, err := os.ReadDir(authDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []*Account{}, nil
		}
		return nil, err
	}
	var out []*Account
	seen := map[string]bool{}
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(strings.ToLower(ent.Name()), ".json") {
			continue
		}
		fullPath := filepath.Join(authDir, ent.Name())
		raw, err := os.ReadFile(fullPath)
		if err != nil {
			continue
		}
		fileUID := strings.TrimSuffix(ent.Name(), filepath.Ext(ent.Name()))
		var acct *Account
		needsReencrypt := false

		if IsLocalEncryptedEnvelope(raw) {
			opened, oerr := vault.OpenAccount(fileUID, raw)
			if oerr != nil {
				log.Printf("WARN: [auth] skip %s: %v", ent.Name(), oerr)
				continue
			}
			acct = opened
		} else {
			// Seal unencrypted account files placed in authDir.
			var plain Account
			if jerr := json.Unmarshal(raw, &plain); jerr != nil {
				continue
			}
			if plain.AccessToken == "" && plain.RefreshToken == "" {
				continue
			}
			acct = &plain
			needsReencrypt = true
		}

		if acct.UID == "" {
			acct.UID = fileUID
		}
		if !ValidUID(acct.UID) || seen[acct.UID] {
			continue
		}
		if !IsDeviceID(acct.DeviceID) {
			acct.DeviceID = NewUUID()
		}
		acct.Provider = NormalizeProvider(acct.Provider)
		acct.Stage = NormalizeStage(acct.Stage)
		if needsReencrypt {
			if serr := SaveAccount(authDir, vault, acct); serr != nil {
				log.Printf("WARN: [auth] encrypt credential %s failed: %v", acct.UID, serr)
			} else {
				log.Printf("[auth] sealed credential %s with AES-256-GCM", acct.UID)
			}
		}
		seen[acct.UID] = true
		out = append(out, acct)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].UID < out[j].UID
	})
	return out, nil
}

// SaveAccount encrypts acct with vault and atomically writes it to authDir/<uid>.json (0600).
func SaveAccount(authDir string, vault *Vault, acct *Account) error {
	if vault == nil {
		return fmt.Errorf("vault is required to save credentials")
	}
	if acct == nil || !ValidUID(acct.UID) {
		return fmt.Errorf("invalid account uid")
	}
	if !IsDeviceID(acct.DeviceID) {
		acct.DeviceID = NewUUID()
	}
	sealed, err := vault.SealAccount(acct)
	if err != nil {
		return err
	}
	path := filepath.Join(authDir, acct.UID+".json")
	return safefile.WriteAtomic(path, sealed, 0o600)
}

// DeleteAccount removes authDir/<uid>.json if present.
func DeleteAccount(authDir, uid string) error {
	if !ValidUID(uid) {
		return fmt.Errorf("invalid account uid %q", uid)
	}
	path := filepath.Join(authDir, uid+".json")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
