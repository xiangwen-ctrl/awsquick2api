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

type credentialFile struct {
	name string
	path string
	raw  []byte
}

// LoadDir reads and decrypts all *.json credential files from authDir using vault.
//
// Loading is two-phase. Encrypted envelopes are loaded first and are authoritative. Legacy
// plaintext files are considered afterwards: a plaintext file for an account that already
// exists in encrypted form is a stale copy (its tokens may have been rotated since), so it
// is deleted instead of overwriting the encrypted credential. Any other plaintext file is
// sealed, and the plaintext source is deleted once the encrypted file is safely on disk.
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
	var encrypted, plaintext []credentialFile
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(strings.ToLower(ent.Name()), ".json") {
			continue
		}
		fullPath := filepath.Join(authDir, ent.Name())
		raw, err := os.ReadFile(fullPath)
		if err != nil {
			log.Printf("WARN: [auth] skip %s: %v", ent.Name(), err)
			continue
		}
		cf := credentialFile{name: ent.Name(), path: fullPath, raw: raw}
		if IsLocalEncryptedEnvelope(raw) {
			encrypted = append(encrypted, cf)
		} else {
			plaintext = append(plaintext, cf)
		}
	}

	var out []*Account
	seen := map[string]bool{}
	loaded := map[string]bool{}

	// Phase 1: encrypted credentials.
	for _, cf := range encrypted {
		fileUID := strings.TrimSuffix(cf.name, filepath.Ext(cf.name))
		acct, oerr := vault.OpenAccount(fileUID, cf.raw)
		if oerr != nil {
			log.Printf("WARN: [auth] skip %s: %v", cf.name, oerr)
			continue
		}
		if acct.UID == "" {
			acct.UID = fileUID
		}
		if !ValidUID(acct.UID) || seen[acct.UID] {
			continue
		}
		normalizeLoadedAccount(acct)
		seen[acct.UID] = true
		loaded[acct.UID] = true
		out = append(out, acct)
	}

	// Phase 2: legacy plaintext credentials.
	for _, cf := range plaintext {
		var plain Account
		if jerr := json.Unmarshal(cf.raw, &plain); jerr != nil {
			continue
		}
		if plain.AccessToken == "" && plain.RefreshToken == "" {
			continue
		}
		fileUID := strings.TrimSuffix(cf.name, filepath.Ext(cf.name))
		if plain.UID == "" {
			plain.UID = fileUID
		}
		if !ValidUID(plain.UID) {
			continue
		}
		if seen[plain.UID] {
			// An encrypted credential for this account is already loaded and authoritative.
			removePlaintextCredential(authDir, cf.path, plain.UID, "superseded by encrypted credential")
			continue
		}
		acct := &plain
		normalizeLoadedAccount(acct)
		if serr := SaveAccount(authDir, vault, acct); serr != nil {
			log.Printf("WARN: [auth] encrypt credential %s failed: %v", acct.UID, serr)
		} else {
			log.Printf("[auth] sealed credential %s with AES-256-GCM", acct.UID)
			removePlaintextCredential(authDir, cf.path, acct.UID, "sealed")
			seen[acct.UID] = true
		}
		if !loaded[acct.UID] {
			loaded[acct.UID] = true
			out = append(out, acct)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].UID < out[j].UID
	})
	return out, nil
}

func normalizeLoadedAccount(acct *Account) {
	if !IsDeviceID(acct.DeviceID) {
		acct.DeviceID = NewUUID()
	}
	acct.Provider = NormalizeProvider(acct.Provider)
	acct.Stage = NormalizeStage(acct.Stage)
}

// removePlaintextCredential deletes a legacy plaintext credential file unless it is the file
// that now holds the sealed credential (same name, or the same file on a case-insensitive
// filesystem).
func removePlaintextCredential(authDir, path, uid, why string) {
	sealedPath := filepath.Join(authDir, uid+".json")
	if path == sealedPath {
		return
	}
	src, err := os.Stat(path)
	if err != nil {
		return
	}
	if dst, err := os.Stat(sealedPath); err == nil && os.SameFile(src, dst) {
		return
	}
	if err := os.Remove(path); err != nil {
		log.Printf("WARN: [auth] could not remove plaintext credential %s (%s): %v", filepath.Base(path), why, err)
		return
	}
	log.Printf("[auth] removed plaintext credential %s (%s)", filepath.Base(path), why)
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
