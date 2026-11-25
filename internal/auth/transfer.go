package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/crypto/scrypt"
)

const (
	encryptedBundleFormat = "awsquick2api-encrypted-v1"
	minPassphraseLen      = 12
	scryptN               = 1 << 15 // 32768
	scryptR               = 8
	scryptP               = 1
	aesKeyLen             = 32
)

// EncryptedBundle is an AES-256-GCM + scrypt encrypted account migration file.
type EncryptedBundle struct {
	Format     string `json:"format"`
	ExportedAt string `json:"exported_at"`
	Count      int    `json:"count"`
	KDF        struct {
		Name string `json:"name"`
		Salt string `json:"salt"`
		N    int    `json:"n"`
		R    int    `json:"r"`
		P    int    `json:"p"`
	} `json:"kdf"`
	Cipher     string `json:"cipher"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type plainBundlePayload struct {
	Accounts []*Account `json:"accounts"`
}

// EncryptAccounts seals accounts into an AES-256-GCM encrypted JSON bundle using scrypt.
func EncryptAccounts(accounts []*Account, passphrase string) ([]byte, error) {
	if len(passphrase) < minPassphraseLen {
		return nil, fmt.Errorf("加密密码长度至少需要 %d 位", minPassphraseLen)
	}
	plain, err := json.Marshal(plainBundlePayload{Accounts: accounts})
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, aesKeyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
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
	ct := gcm.Seal(nil, nonce, plain, []byte(encryptedBundleFormat))

	var bundle EncryptedBundle
	bundle.Format = encryptedBundleFormat
	bundle.ExportedAt = time.Now().UTC().Format(time.RFC3339)
	bundle.Count = len(accounts)
	bundle.KDF.Name = "scrypt"
	bundle.KDF.Salt = base64.StdEncoding.EncodeToString(salt)
	bundle.KDF.N = scryptN
	bundle.KDF.R = scryptR
	bundle.KDF.P = scryptP
	bundle.Cipher = "aes-256-gcm"
	bundle.Nonce = base64.StdEncoding.EncodeToString(nonce)
	bundle.Ciphertext = base64.StdEncoding.EncodeToString(ct)

	out, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// IsEncryptedBundle reports whether raw JSON looks like an EncryptedBundle.
func IsEncryptedBundle(raw []byte) bool {
	var probe struct {
		Format string `json:"format"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}
	return probe.Format == encryptedBundleFormat
}

// maxScryptMemory caps the scrypt working set (128*N*r bytes) accepted from an import file,
// so a crafted bundle cannot make the gateway allocate gigabytes and get OOM-killed.
const (
	maxScryptMemory = 64 << 20
	maxScryptWork   = 1 << 20
)

// scryptParamsSafe validates untrusted scrypt parameters before any key derivation runs.
func scryptParamsSafe(n, r, p int) bool {
	if n < 16384 || n > 1<<20 || n&(n-1) != 0 || r < 1 || r > 32 || p < 1 || p > 16 {
		return false
	}
	return int64(128)*int64(n)*int64(r) <= maxScryptMemory &&
		int64(128)*int64(r)*int64(p) <= maxScryptMemory &&
		int64(n)*int64(r)*int64(p) <= maxScryptWork
}

// DecryptAccounts decrypts an EncryptedBundle using passphrase and returns the accounts.
func DecryptAccounts(raw []byte, passphrase string) ([]*Account, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("需要提供解密密码")
	}
	var bundle EncryptedBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return nil, fmt.Errorf("解析加密文件失败: %w", err)
	}
	if bundle.Format != encryptedBundleFormat {
		return nil, fmt.Errorf("不支持的加密格式 %q", bundle.Format)
	}
	if bundle.KDF.Name != "scrypt" || bundle.Cipher != "aes-256-gcm" {
		return nil, fmt.Errorf("不支持的加密算法参数")
	}
	if !scryptParamsSafe(bundle.KDF.N, bundle.KDF.R, bundle.KDF.P) {
		return nil, fmt.Errorf("KDF 参数超出安全范围")
	}
	salt, err := base64.StdEncoding.DecodeString(bundle.KDF.Salt)
	if err != nil || len(salt) < 8 {
		return nil, fmt.Errorf("加密文件 salt 无效")
	}
	nonce, err := base64.StdEncoding.DecodeString(bundle.Nonce)
	if err != nil {
		return nil, fmt.Errorf("加密文件 nonce 无效")
	}
	ct, err := base64.StdEncoding.DecodeString(bundle.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("加密文件密文无效")
	}

	key, err := scrypt.Key([]byte(passphrase), salt, bundle.KDF.N, bundle.KDF.R, bundle.KDF.P, aesKeyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("加密文件 nonce 长度不匹配")
	}
	plain, err := gcm.Open(nil, nonce, ct, []byte(encryptedBundleFormat))
	if err != nil {
		return nil, fmt.Errorf("解密失败：密码错误或文件已损坏")
	}

	var payload plainBundlePayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return nil, fmt.Errorf("解析解密后的账号数据失败: %w", err)
	}
	out := make([]*Account, 0, len(payload.Accounts))
	for _, a := range payload.Accounts {
		if a == nil {
			continue
		}
		a.Provider = NormalizeProvider(a.Provider)
		a.Stage = NormalizeStage(a.Stage)
		if !ValidUID(a.UID) {
			a.UID = MakeUID(a.Provider, firstNonEmpty(a.Email, a.AccountID, a.AWSAccountID))
		}
		if !IsDeviceID(a.DeviceID) {
			a.DeviceID = NewUUID()
		}
		out = append(out, a)
	}
	return out, nil
}
