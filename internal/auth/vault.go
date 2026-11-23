package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"awsquick2api/internal/safefile"
)

const localVaultFormat = "awsquick2api-local-aes256gcm-v1"

// Vault encrypts and decrypts local account credential files using a 32-byte AES-256-GCM master key.
type Vault struct {
	key []byte
}

type localEnvelope struct {
	Format     string `json:"format"`
	UID        string `json:"uid"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// OpenOrCreateVault loads a 32-byte key from envKey (if non-empty) or keyPath.
// If keyPath does not exist, a fresh cryptographically random 32-byte key is generated and written atomically (0600).
func OpenOrCreateVault(keyPath, envKey string) (*Vault, error) {
	if raw := strings.TrimSpace(envKey); raw != "" {
		k, err := decodeOrDeriveKey(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid encryption key from env: %w", err)
		}
		return &Vault{key: k}, nil
	}
	if strings.TrimSpace(keyPath) == "" {
		return nil, errors.New("encryption key path is empty")
	}
	data, err := os.ReadFile(keyPath)
	if err == nil {
		k, derr := decodeOrDeriveKey(strings.TrimSpace(string(data)))
		if derr != nil {
			return nil, fmt.Errorf("invalid encryption key in %s: %w", keyPath, derr)
		}
		return &Vault{key: k}, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read encryption key %s: %w", keyPath, err)
	}

	key := make([]byte, 32)
	if _, rerr := rand.Read(key); rerr != nil {
		return nil, fmt.Errorf("generate encryption key: %w", rerr)
	}
	encoded := base64.StdEncoding.EncodeToString(key) + "\n"
	if werr := safefile.WriteAtomic(keyPath, []byte(encoded), 0o600); werr != nil {
		return nil, fmt.Errorf("write encryption key %s: %w", keyPath, werr)
	}
	return &Vault{key: key}, nil
}

// NewVaultFromKey constructs an in-memory Vault from a 32-byte key (useful for tests).
func NewVaultFromKey(key []byte) (*Vault, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("vault key must be 32 bytes, got %d", len(key))
	}
	cp := make([]byte, 32)
	copy(cp, key)
	return &Vault{key: cp}, nil
}

func decodeOrDeriveKey(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("empty key")
	}
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil && len(raw) == 32 {
		return raw, nil
	}
	if raw, err := base64.RawURLEncoding.DecodeString(s); err == nil && len(raw) == 32 {
		return raw, nil
	}
	if len(s) >= 16 {
		sum := sha256.Sum256([]byte(s))
		return sum[:], nil
	}
	return nil, errors.New("key must be base64-encoded 32 bytes or at least 16 characters")
}

// IsLocalEncryptedEnvelope reports whether raw JSON is a local AES-256-GCM sealed account envelope.
func IsLocalEncryptedEnvelope(raw []byte) bool {
	var probe struct {
		Format string `json:"format"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}
	return probe.Format == localVaultFormat
}

// SealAccount encrypts acct into a JSON envelope authenticated with uid as AAD.
func (v *Vault) SealAccount(acct *Account) ([]byte, error) {
	if v == nil || len(v.key) != 32 {
		return nil, errors.New("vault not initialized")
	}
	if acct == nil || !ValidUID(acct.UID) {
		return nil, errors.New("invalid account uid")
	}
	plain, err := json.Marshal(acct)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	aad := []byte(localVaultFormat + ":" + acct.UID)
	ct := gcm.Seal(nil, nonce, plain, aad)

	env := localEnvelope{
		Format:     localVaultFormat,
		UID:        acct.UID,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}
	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// OpenAccount decrypts a sealed local envelope back into an Account.
func (v *Vault) OpenAccount(expectedUID string, raw []byte) (*Account, error) {
	if v == nil || len(v.key) != 32 {
		return nil, errors.New("vault not initialized")
	}
	var env localEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if env.Format != localVaultFormat {
		return nil, fmt.Errorf("unexpected envelope format %q", env.Format)
	}
	uid := env.UID
	if expectedUID != "" && uid != expectedUID {
		return nil, fmt.Errorf("envelope uid mismatch (%q != %q)", uid, expectedUID)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, errors.New("invalid envelope nonce")
	}
	ct, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, errors.New("invalid envelope ciphertext")
	}
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid nonce size")
	}
	aad := []byte(localVaultFormat + ":" + uid)
	plain, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, errors.New("failed to decrypt local account credential (wrong encryption.key or corrupted file)")
	}
	var acct Account
	if err := json.Unmarshal(plain, &acct); err != nil {
		return nil, err
	}
	return &acct, nil
}
