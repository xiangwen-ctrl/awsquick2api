// Package auth manages Amazon Quick account credentials, native desktop PKCE OAuth
// (personal social/IdC, enterprise SSO, and gateway transports), loopback & pasted
// callback flows, token refresh, atomic credential persistence, and encrypted migration.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	ProviderSocial        = "social"
	ProviderEnterprise    = "enterprise"
	ProviderGateway       = "gateway"
	ProviderSocialGateway = "social_gateway"

	GatewayWSPath = "/ws/service/SpaceNeedleConversationService/operation/ChatBidirectionalStream"
	DefaultWSPath = "/streaming/quickwork-chat-bidirectional-stream"
)

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Account represents one persisted Amazon Quick desktop OAuth account credential.
type Account struct {
	UID                   string `json:"uid"`
	AccountID             string `json:"account_id,omitempty"`
	Email                 string `json:"email,omitempty"`
	UserName              string `json:"user_name,omitempty"`
	DisplayNameVal        string `json:"display_name,omitempty"`
	CustomName            string `json:"custom_name,omitempty"`
	AccountName           string `json:"account_name,omitempty"`
	ActorARN              string `json:"actor_arn,omitempty"`
	AWSAccountID          string `json:"aws_account_id,omitempty"`
	Provider              string `json:"provider"` // social | enterprise | gateway | social_gateway
	Stage                 string `json:"stage"`    // prod | beta | integ | dev
	Region                string `json:"region"`
	IDCRegion             string `json:"idc_region,omitempty"`
	TenantURL             string `json:"tenant_url"`
	WSHost                string `json:"ws_host"`
	WSPath                string `json:"ws_path,omitempty"`
	Namespace             string `json:"namespace,omitempty"`
	IssuerURL             string `json:"issuer_url,omitempty"`
	TokenEndpoint         string `json:"token_endpoint,omitempty"`
	RedirectURI           string `json:"redirect_uri,omitempty"`
	ClientID              string `json:"client_id,omitempty"`
	ClientSecret          string `json:"client_secret,omitempty"`
	ClientSecretExpiresAt int64  `json:"client_secret_expires_at,omitempty"`
	AccessToken           string `json:"access_token"`
	RefreshToken          string `json:"refresh_token"`
	IDToken               string `json:"id_token,omitempty"`
	ExpiresAt             int64  `json:"expires_at"` // Unix milliseconds
	DeviceID              string `json:"device_id"`  // Stable UUID v4 sent as outpostId
	AddedAt               int64  `json:"added_at,omitempty"`
	UpdatedAt             int64  `json:"updated_at,omitempty"`
}

// NormalizeProvider maps raw provider input to a canonical Quick provider name.
func NormalizeProvider(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case ProviderEnterprise:
		return ProviderEnterprise
	case ProviderGateway:
		return ProviderGateway
	case ProviderSocialGateway:
		return ProviderSocialGateway
	default:
		return ProviderSocial
	}
}

// NormalizeStage maps raw stage input to prod/beta/integ/dev.
func NormalizeStage(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "beta", "integ", "dev":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return "prod"
	}
}

// IsEnterpriseDiscovery reports whether provider uses the enterprise discovery/form OAuth branch.
func IsEnterpriseDiscovery(provider string) bool {
	p := NormalizeProvider(provider)
	return p == ProviderEnterprise || p == ProviderGateway
}

// IsGatewayProvider reports whether provider uses the CBOR Gateway bidi transport.
func IsGatewayProvider(provider string) bool {
	p := NormalizeProvider(provider)
	return p == ProviderGateway || p == ProviderSocialGateway
}

// IsGateway reports whether this account uses the CBOR Gateway bidi transport.
func (a *Account) IsGateway() bool {
	if a == nil {
		return false
	}
	return IsGatewayProvider(a.Provider)
}

// IsEnterprise reports whether this account uses enterprise form OAuth token exchange.
func (a *Account) IsEnterprise() bool {
	if a == nil {
		return false
	}
	return IsEnterpriseDiscovery(a.Provider)
}

// ProviderLabel returns a human-readable Chinese/English tag for UI display.
func (a *Account) ProviderLabel() string {
	if a == nil {
		return "个人"
	}
	switch NormalizeProvider(a.Provider) {
	case ProviderEnterprise:
		return "企业"
	case ProviderGateway:
		return "企业 Gateway"
	case ProviderSocialGateway:
		return "个人 Gateway"
	default:
		return "个人"
	}
}

// DisplayName returns custom_name > email > display_name > account_id > uid.
func (a *Account) DisplayName() string {
	if a == nil {
		return ""
	}
	for _, s := range []string{a.CustomName, a.Email, a.DisplayNameVal, a.UserName, a.AccountID, a.UID} {
		if t := strings.TrimSpace(s); t != "" {
			return t
		}
	}
	return ""
}

// WSBearer returns the bearer JWT used for WebSocket chat handshakes.
// Social/Gateway transports use access_token; enterprise AIDP prefers id_token (fallback access_token).
func (a *Account) WSBearer() string {
	if a == nil {
		return ""
	}
	if NormalizeProvider(a.Provider) == ProviderEnterprise {
		if t := strings.TrimSpace(a.IDToken); t != "" {
			return t
		}
		return strings.TrimSpace(a.AccessToken)
	}
	if t := strings.TrimSpace(a.AccessToken); t != "" {
		return t
	}
	return strings.TrimSpace(a.IDToken)
}

// NeedsRefresh reports whether the access token is expired or within advance of expiry.
func (a *Account) NeedsRefresh(now time.Time, advance time.Duration) bool {
	if a == nil || strings.TrimSpace(a.RefreshToken) == "" || a.RefreshToken == "none" {
		return false
	}
	if a.ExpiresAt <= 0 {
		return false
	}
	return now.Add(advance).UnixMilli() >= a.ExpiresAt
}

// IsDeviceID reports whether value is a valid UUID string.
func IsDeviceID(value string) bool {
	return uuidRE.MatchString(strings.TrimSpace(value))
}

// NewUUID generates a random RFC 4122 UUID v4 string.
func NewUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
		copy(b[:], sum[:16])
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// MakeUID derives a deterministic, filename-safe UID from provider and account identity.
func MakeUID(provider, identity string) string {
	p := NormalizeProvider(provider)
	prefix := "aq_"
	switch p {
	case ProviderEnterprise:
		prefix = "ent_"
	case ProviderGateway:
		prefix = "gw_"
	case ProviderSocialGateway:
		prefix = "sgw_"
	default:
		prefix = "soc_"
	}

	ident := strings.ToLower(strings.TrimSpace(identity))
	if ident == "" {
		var b [6]byte
		_, _ = rand.Read(b[:])
		return prefix + hex.EncodeToString(b[:])
	}

	var sb strings.Builder
	sb.WriteString(prefix)
	for i := 0; i < len(ident); i++ {
		c := ident[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' {
			sb.WriteByte(c)
		} else if c == '@' || c == '.' {
			sb.WriteByte('_')
		}
	}
	sum := sha256.Sum256([]byte(p + "|" + ident))
	suffix := hex.EncodeToString(sum[:4])
	base := strings.Trim(sb.String(), "_")
	if len(base) > 48 {
		base = base[:48]
	}
	if base == "" || base == strings.TrimSuffix(prefix, "_") {
		return prefix + suffix
	}
	return base + "_" + suffix
}

// ValidUID enforces a strict allowlist preventing path traversal and Windows reserved filenames.
func ValidUID(uid string) bool {
	if uid == "" || len(uid) > 80 || uid == "." {
		return false
	}
	for i := 0; i < len(uid); i++ {
		c := uid[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'
		if !ok {
			return false
		}
	}
	if strings.Contains(uid, "..") || strings.HasSuffix(uid, ".") {
		return false
	}
	base := uid
	if dot := strings.IndexByte(base, '.'); dot >= 0 {
		base = base[:dot]
	}
	switch strings.ToUpper(base) {
	case "CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return false
	}
	return true
}

// Clone returns a shallow copy of Account.
func (a *Account) Clone() *Account {
	if a == nil {
		return nil
	}
	cp := *a
	return &cp
}
