// Package config loads, validates, defaults, and atomically saves awsquick2api configuration.
package config

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"awsquick2api/internal/safefile"
)

const (
	// DefaultMaxFrameBytes keeps composed frames safely under Amazon Quick's 64 KB single-frame limit.
	DefaultMaxFrameBytes = 63000
	// MinMaxFrameBytes is the smallest accepted max_frame_bytes; smaller values cannot fit a prompt.
	MinMaxFrameBytes = 8192
)

// Config is the root configuration structure for awsquick2api.
type Config struct {
	Listen   string         `json:"listen"`
	APIKey   string         `json:"api_key"`
	AdminKey string         `json:"admin_key"`
	AuthDir  string         `json:"auth_dir"`
	DataDir  string         `json:"data_dir"`
	Server   ServerConfig   `json:"server"`
	Upstream UpstreamConfig `json:"upstream"`
	Pool     PoolConfig     `json:"pool"`
	Thinking ThinkingConfig `json:"thinking"`
	Schedule ScheduleConfig `json:"schedule"`
	Session  SessionConfig  `json:"session"`
	Features FeaturesConfig `json:"features"`
	Models   ModelsConfig   `json:"models"`
}

const (
	DefaultMaxPayloadBytes         = 24 << 20
	DefaultMaxInflightPayloadBytes = 32 << 20
	ExampleAPIKey                  = "replace_with_your_api_key"
	ExampleAdminKey                = "replace_with_your_admin_key"
)

type ServerConfig struct {
	ReadTimeoutSeconds      int      `json:"read_timeout_seconds"`
	ShutdownTimeoutSeconds  int      `json:"shutdown_timeout_seconds"`
	MaxPayloadBytes         int64    `json:"max_payload_bytes"`
	MaxInflightPayloadBytes int64    `json:"max_inflight_payload_bytes"`
	TrustedHosts            []string `json:"trusted_hosts,omitempty"`
	CORSAllowedOrigins      []string `json:"cors_allowed_origins,omitempty"`
}

type UpstreamConfig struct {
	AppVersion              string `json:"app_version"`
	Surface                 string `json:"surface"`
	Stage                   string `json:"stage"`          // "prod" | "beta" | "integ" | "dev"
	DefaultRegion           string `json:"default_region"` // default "us-east-1"
	CallbackPort            int    `json:"callback_port"`  // default 18080
	ProxyURL                string `json:"proxy_url"`      // optional single outbound HTTP/HTTPS/SOCKS5 proxy
	TimeoutSeconds          int    `json:"timeout_seconds"`
	HandshakeTimeoutSeconds int    `json:"handshake_timeout_seconds"`
	IdleTimeoutSeconds      int    `json:"idle_timeout_seconds"`
	HeaderWaitSeconds       int    `json:"header_wait_seconds"`
	KeepaliveSeconds        int    `json:"keepalive_seconds"`
	Timezone                string `json:"timezone"`
	Locale                  string `json:"locale"`
	DefaultModel            string `json:"default_model"`
	Stateful                bool   `json:"single_client_thread_reuse"`
	Attachments             bool   `json:"attachments"`
	MaxFrameBytes           int    `json:"max_frame_bytes"`
	KeepSessions            bool   `json:"keep_sessions"`
	WebSearch               bool   `json:"web_search"`
	ShowQuickTools          bool   `json:"show_quick_tools"`
	StableDeviceID          bool   `json:"stable_device_id"`
	OIDCBase                string `json:"oidc_base,omitempty"`
	DiscoveryURL            string `json:"discovery_url,omitempty"`
	DataPlaneURL            string `json:"data_plane_url,omitempty"`
}

type PoolConfig struct {
	MaxInFlight        int    `json:"max_in_flight"`
	SoftCooldownSec    int    `json:"soft_cooldown_seconds"`
	SoftCooldownMaxSec int    `json:"soft_cooldown_max_seconds"`
	BreakerThreshold   int    `json:"breaker_threshold"`
	BreakerCooldownSec int    `json:"breaker_cooldown_seconds"`
	SelectionStrategy  string `json:"selection_strategy"` // "weighted" | "round_robin" | "sequential"
	MaxRotate          int    `json:"max_rotate"`
}

type ThinkingConfig struct {
	Policy         string            `json:"policy"`         // "client" | "gateway"
	DefaultEffort  string            `json:"default_effort"` // "off" | "low" | "medium" | "high"
	ModelOverrides map[string]string `json:"model_overrides,omitempty"`
}

type ScheduleConfig struct {
	QuotaRefreshEnabled       bool `json:"quota_refresh_enabled"`
	QuotaRefreshMinutes       int  `json:"quota_refresh_minutes"`
	TokenRefreshEnabled       bool `json:"token_refresh_enabled"`
	TokenRefreshCheckMinutes  int  `json:"token_refresh_check_minutes"`
	TokenRefreshAdvanceMinute int  `json:"token_refresh_advance_minutes"`
}

type SessionConfig struct {
	Enabled    bool `json:"enabled"`
	TTLMinutes int  `json:"ttl_minutes"`
}

type FeaturesConfig struct {
	ClaudeAliases     bool `json:"claude_aliases"`
	RequestArchive    bool `json:"request_archive"`
	EmptyRetryEnabled bool `json:"empty_retry_enabled"`
	StrictPrivacyDLP  bool `json:"strict_privacy_dlp"`
}

type ModelsConfig struct {
	Hidden               []string `json:"hidden"`
	Allowed              []string `json:"allowed"`
	ExposeEffortVariants bool     `json:"expose_effort_variants"`
}

// Default returns a recommended configuration with sane, secure local defaults.
func Default() *Config {
	return &Config{
		Listen:   "127.0.0.1:8045",
		APIKey:   "",
		AdminKey: "",
		AuthDir:  "./auths",
		DataDir:  "./data",
		Server: ServerConfig{
			ReadTimeoutSeconds:      300,
			ShutdownTimeoutSeconds:  30,
			MaxPayloadBytes:         DefaultMaxPayloadBytes,
			MaxInflightPayloadBytes: DefaultMaxInflightPayloadBytes,
		},
		Upstream: UpstreamConfig{
			AppVersion:              "1.2.4660",
			Surface:                 "QUICK_WORK_DESKTOP_WINDOWS",
			Stage:                   "prod",
			DefaultRegion:           "us-east-1",
			CallbackPort:            18080,
			ProxyURL:                "",
			TimeoutSeconds:          300,
			HandshakeTimeoutSeconds: 20,
			IdleTimeoutSeconds:      120,
			HeaderWaitSeconds:       10,
			KeepaliveSeconds:        25,
			Timezone:                "UTC",
			Locale:                  "en-US",
			DefaultModel:            "smart",
			Attachments:             true,
			MaxFrameBytes:           63000,
			KeepSessions:            false,
			WebSearch:               false,
			ShowQuickTools:          true,
			StableDeviceID:          true,
		},
		Pool: PoolConfig{
			MaxInFlight:        2,
			SoftCooldownSec:    60,
			SoftCooldownMaxSec: 3600,
			BreakerThreshold:   3,
			BreakerCooldownSec: 900,
			SelectionStrategy:  "weighted",
			MaxRotate:          3,
		},
		Thinking: ThinkingConfig{
			Policy:         "client",
			DefaultEffort:  "off",
			ModelOverrides: map[string]string{},
		},
		Schedule: ScheduleConfig{
			QuotaRefreshEnabled:       true,
			QuotaRefreshMinutes:       10,
			TokenRefreshEnabled:       true,
			TokenRefreshCheckMinutes:  1,
			TokenRefreshAdvanceMinute: 10,
		},
		Session: SessionConfig{
			Enabled:    true,
			TTLMinutes: 30,
		},
		Features: FeaturesConfig{
			ClaudeAliases:     true,
			RequestArchive:    true,
			EmptyRetryEnabled: true,
			StrictPrivacyDLP:  true,
		},
		Models: ModelsConfig{
			Hidden:               []string{},
			Allowed:              []string{},
			ExposeEffortVariants: false,
		},
	}
}

func randomHexKey(prefix string) string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("config: crypto/rand failed: %v", err))
	}
	return prefix + hex.EncodeToString(b)
}

// GenerateAPIKey generates a cryptographically random "qk_" prefixed API key.
func GenerateAPIKey() string { return randomHexKey("qk_") }

// GenerateAdminKey generates a cryptographically random "qka_" prefixed panel admin key.
func GenerateAdminKey() string { return randomHexKey("qka_") }

// ValidAPIKey reports whether a configured inference key is usable.
func ValidAPIKey(key string) bool {
	key = strings.TrimSpace(key)
	return key != "" && key != ExampleAPIKey
}

// ValidAdminKey reports whether a configured panel admin key is usable.
func ValidAdminKey(key string) bool {
	key = strings.TrimSpace(key)
	return key != "" && key != ExampleAdminKey
}

// WriteDefault creates a fresh config.json with independent random api_key and admin_key.
func WriteDefault(path string) (apiKey string, adminKey string, err error) {
	cfg := Default()
	cfg.APIKey = GenerateAPIKey()
	cfg.AdminKey = GenerateAdminKey()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", "", err
	}
	data = append(data, '\n')
	if err := safefile.WriteAtomic(path, data, 0o600); err != nil {
		return "", "", err
	}
	return cfg.APIKey, cfg.AdminKey, nil
}

// LoadFileOnly reads config from path over defaults and normalizes it without env overrides.
func LoadFileOnly(path string) (*Config, error) {
	cfg := Default()
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config %s: %w", path, err)
		}
		raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})
		if err := json.Unmarshal(raw, cfg); err != nil {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
	}
	cfg.normalize()
	return cfg, nil
}

// Load reads config from path, applies defaults and environment overrides.
func Load(path string) (*Config, error) {
	cfg, err := LoadFileOnly(path)
	if err != nil {
		return nil, err
	}
	cfg.applyEnv()
	cfg.normalize()
	return cfg, nil
}

// LoadOrCreate loads path, or writes a default config with independent api_key and admin_key.
// If an existing config.json predates admin_key, a fresh admin_key is generated and persisted atomically.
func LoadOrCreate(path string) (*Config, bool, error) {
	cfg, err := Load(path)
	if err == nil {
		if strings.TrimSpace(cfg.AdminKey) == "" && path != "" && strings.TrimSpace(os.Getenv("AWSQUICK_ADMIN_KEY")) == "" {
			if diskCfg, derr := LoadFileOnly(path); derr == nil && strings.TrimSpace(diskCfg.AdminKey) == "" {
				diskCfg.AdminKey = GenerateAdminKey()
				// Always use the generated key for this process so the panel is never
				// left without an admin key; persist it so restarts keep the same key.
				cfg.AdminKey = diskCfg.AdminKey
				raw, merr := json.MarshalIndent(diskCfg, "", "  ")
				if merr == nil {
					merr = safefile.WriteAtomic(path, append(raw, '\n'), 0o600)
				}
				if merr != nil {
					log.Printf("WARN: [config] generated admin_key but failed to persist it to %s: %v; the key is ephemeral until config.json is writable", path, merr)
				} else {
					log.Printf("[config] admin_key was empty; generated and persisted a new one in %s", path)
				}
			}
		}
		return cfg, false, nil
	}
	if !errors.Is(err, fs.ErrNotExist) || path == "" {
		return nil, false, err
	}
	_, _, werr := WriteDefault(path)
	if werr != nil {
		def := Default()
		def.APIKey = GenerateAPIKey()
		def.AdminKey = GenerateAdminKey()
		def.applyEnv()
		def.normalize()
		log.Printf("WARN: [config] failed to write default config %s: %v; using ephemeral keys in memory", path, werr)
		return def, false, nil
	}
	cfg, err = Load(path)
	if err != nil {
		return nil, false, err
	}
	return cfg, true, nil
}

var envOverrideVars = []string{
	"AWSQUICK_ADMIN_KEY",
	"AWSQUICK_API_KEY",
	"AWSQUICK_APP_VERSION",
	"AWSQUICK_AUTH_DIR",
	"AWSQUICK_CALLBACK_PORT",
	"AWSQUICK_CORS_ORIGINS",
	"AWSQUICK_DATA_DIR",
	"AWSQUICK_DATA_PLANE_URL",
	"AWSQUICK_DEFAULT_REGION",
	"AWSQUICK_DISCOVERY_URL",
	"AWSQUICK_ENCRYPTION_KEY",
	"AWSQUICK_LISTEN",
	"AWSQUICK_OIDC_BASE",
	"AWSQUICK_PROXY_URL",
	"AWSQUICK_STAGE",
	"AWSQUICK_TRUSTED_HOSTS",
}

func ActiveEnvOverrides() []string {
	var active []string
	for _, k := range envOverrideVars {
		if strings.TrimSpace(os.Getenv(k)) != "" {
			active = append(active, k)
		}
	}
	return active
}

func (c *Config) applyEnv() {
	if v := strings.TrimSpace(os.Getenv("AWSQUICK_LISTEN")); v != "" {
		c.Listen = v
	}
	if v := strings.TrimSpace(os.Getenv("AWSQUICK_API_KEY")); v != "" {
		c.APIKey = v
	}
	if v := strings.TrimSpace(os.Getenv("AWSQUICK_ADMIN_KEY")); v != "" {
		c.AdminKey = v
	}
	if v := strings.TrimSpace(os.Getenv("AWSQUICK_AUTH_DIR")); v != "" {
		c.AuthDir = v
	}
	if v := strings.TrimSpace(os.Getenv("AWSQUICK_DATA_DIR")); v != "" {
		c.DataDir = v
	}
	if v := strings.TrimSpace(os.Getenv("AWSQUICK_CALLBACK_PORT")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 65535 {
			c.Upstream.CallbackPort = n
		}
	}
	if v := strings.TrimSpace(os.Getenv("AWSQUICK_PROXY_URL")); v != "" {
		c.Upstream.ProxyURL = v
	}
	if v := strings.TrimSpace(os.Getenv("AWSQUICK_APP_VERSION")); v != "" {
		c.Upstream.AppVersion = v
	}
	if v := strings.TrimSpace(os.Getenv("AWSQUICK_STAGE")); v != "" {
		c.Upstream.Stage = v
	}
	if v := strings.TrimSpace(os.Getenv("AWSQUICK_DEFAULT_REGION")); v != "" {
		c.Upstream.DefaultRegion = v
	}
	if v := strings.TrimSpace(os.Getenv("AWSQUICK_OIDC_BASE")); v != "" {
		c.Upstream.OIDCBase = strings.TrimRight(v, "/")
	}
	if v := strings.TrimSpace(os.Getenv("AWSQUICK_DISCOVERY_URL")); v != "" {
		c.Upstream.DiscoveryURL = v
	}
	if v := strings.TrimSpace(os.Getenv("AWSQUICK_DATA_PLANE_URL")); v != "" {
		c.Upstream.DataPlaneURL = strings.TrimRight(v, "/")
	}
	if v := strings.TrimSpace(os.Getenv("AWSQUICK_TRUSTED_HOSTS")); v != "" {
		var hosts []string
		for _, part := range strings.Split(v, ",") {
			if h := strings.TrimSpace(part); h != "" {
				hosts = append(hosts, h)
			}
		}
		c.Server.TrustedHosts = hosts
	}
	if v := strings.TrimSpace(os.Getenv("AWSQUICK_CORS_ORIGINS")); v != "" {
		var origins []string
		for _, part := range strings.Split(v, ",") {
			if o := strings.TrimSpace(part); o != "" {
				origins = append(origins, o)
			}
		}
		c.Server.CORSAllowedOrigins = origins
	}
}

func (c *Config) normalize() {
	if strings.TrimSpace(c.Listen) == "" {
		c.Listen = "127.0.0.1:8045"
	}
	if strings.TrimSpace(c.AuthDir) == "" {
		c.AuthDir = "./auths"
	}
	if strings.TrimSpace(c.DataDir) == "" {
		c.DataDir = "./data"
	}
	if c.Server.ReadTimeoutSeconds < 0 {
		c.Server.ReadTimeoutSeconds = 300
	}
	if c.Server.ShutdownTimeoutSeconds <= 0 {
		c.Server.ShutdownTimeoutSeconds = 30
	}
	if c.Server.MaxPayloadBytes <= 0 {
		c.Server.MaxPayloadBytes = DefaultMaxPayloadBytes
	}
	if c.Server.MaxPayloadBytes < 8<<20 {
		c.Server.MaxPayloadBytes = 8 << 20
	}
	if c.Server.MaxPayloadBytes > 512<<20 {
		c.Server.MaxPayloadBytes = 512 << 20
	}
	if c.Server.MaxInflightPayloadBytes <= 0 {
		c.Server.MaxInflightPayloadBytes = DefaultMaxInflightPayloadBytes
	}
	if c.Server.MaxInflightPayloadBytes < 8<<20 {
		c.Server.MaxInflightPayloadBytes = 8 << 20
	}
	if c.Server.MaxInflightPayloadBytes > 512<<20 {
		c.Server.MaxInflightPayloadBytes = 512 << 20
	}
	c.APIKey = strings.TrimSpace(c.APIKey)
	c.AdminKey = strings.TrimSpace(c.AdminKey)
	if len(c.Server.TrustedHosts) > 0 {
		seen := make(map[string]bool, len(c.Server.TrustedHosts))
		cleaned := make([]string, 0, len(c.Server.TrustedHosts))
		for _, h := range c.Server.TrustedHosts {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			low := strings.ToLower(h)
			if seen[low] {
				continue
			}
			seen[low] = true
			cleaned = append(cleaned, h)
		}
		c.Server.TrustedHosts = cleaned
	}
	if len(c.Server.CORSAllowedOrigins) > 0 {
		seen := make(map[string]bool, len(c.Server.CORSAllowedOrigins))
		cleaned := make([]string, 0, len(c.Server.CORSAllowedOrigins))
		for _, o := range c.Server.CORSAllowedOrigins {
			o = strings.TrimRight(strings.TrimSpace(o), "/")
			if o == "" {
				continue
			}
			low := strings.ToLower(o)
			if seen[low] {
				continue
			}
			seen[low] = true
			cleaned = append(cleaned, o)
		}
		c.Server.CORSAllowedOrigins = cleaned
	}

	if strings.TrimSpace(c.Upstream.AppVersion) == "" {
		c.Upstream.AppVersion = "1.2.4660"
	}
	if strings.TrimSpace(c.Upstream.Surface) == "" {
		c.Upstream.Surface = "QUICK_WORK_DESKTOP_WINDOWS"
	}
	switch strings.ToLower(strings.TrimSpace(c.Upstream.Stage)) {
	case "prod", "beta", "integ", "dev":
		c.Upstream.Stage = strings.ToLower(strings.TrimSpace(c.Upstream.Stage))
	default:
		c.Upstream.Stage = "prod"
	}
	if strings.TrimSpace(c.Upstream.DefaultRegion) == "" {
		c.Upstream.DefaultRegion = "us-east-1"
	}
	if c.Upstream.CallbackPort < 0 || c.Upstream.CallbackPort > 65535 {
		c.Upstream.CallbackPort = 18080
	}
	c.Upstream.ProxyURL = strings.TrimSpace(c.Upstream.ProxyURL)
	if c.Upstream.TimeoutSeconds <= 0 {
		c.Upstream.TimeoutSeconds = 300
	}
	if c.Upstream.HandshakeTimeoutSeconds <= 0 {
		c.Upstream.HandshakeTimeoutSeconds = 20
	}
	if c.Upstream.IdleTimeoutSeconds <= 0 {
		c.Upstream.IdleTimeoutSeconds = 120
	}
	if c.Upstream.HeaderWaitSeconds < 0 {
		c.Upstream.HeaderWaitSeconds = 10
	}
	if c.Upstream.KeepaliveSeconds <= 0 {
		c.Upstream.KeepaliveSeconds = 25
	}
	if strings.TrimSpace(c.Upstream.Timezone) == "" {
		c.Upstream.Timezone = "UTC"
	}
	if strings.TrimSpace(c.Upstream.Locale) == "" {
		c.Upstream.Locale = "en-US"
	}
	switch strings.ToLower(strings.TrimSpace(c.Upstream.DefaultModel)) {
	case "smart", "balanced", "fast", "auto", "advanced":
		c.Upstream.DefaultModel = strings.ToLower(strings.TrimSpace(c.Upstream.DefaultModel))
	default:
		c.Upstream.DefaultModel = "smart"
	}
	// max_frame_bytes drives frame fitting and the 70% FrameTooLarge retry; 0 or
	// negative would silently disable both, so fall back to the safe default.
	if c.Upstream.MaxFrameBytes <= 0 {
		c.Upstream.MaxFrameBytes = DefaultMaxFrameBytes
	}
	if c.Upstream.MaxFrameBytes < MinMaxFrameBytes {
		c.Upstream.MaxFrameBytes = MinMaxFrameBytes
	}
	c.Upstream.OIDCBase = strings.TrimRight(strings.TrimSpace(c.Upstream.OIDCBase), "/")
	c.Upstream.DiscoveryURL = strings.TrimSpace(c.Upstream.DiscoveryURL)
	c.Upstream.DataPlaneURL = strings.TrimRight(strings.TrimSpace(c.Upstream.DataPlaneURL), "/")

	switch strings.ToLower(strings.TrimSpace(c.Thinking.Policy)) {
	case "gateway":
		c.Thinking.Policy = "gateway"
	default:
		c.Thinking.Policy = "client"
	}
	switch strings.ToLower(strings.TrimSpace(c.Thinking.DefaultEffort)) {
	case "low":
		c.Thinking.DefaultEffort = "low"
	case "medium":
		c.Thinking.DefaultEffort = "medium"
	case "high":
		c.Thinking.DefaultEffort = "high"
	default:
		c.Thinking.DefaultEffort = "off"
	}
	if c.Thinking.ModelOverrides == nil {
		c.Thinking.ModelOverrides = map[string]string{}
	}

	if c.Pool.MaxInFlight <= 0 {
		c.Pool.MaxInFlight = 2
	}
	if c.Pool.SoftCooldownSec <= 0 {
		c.Pool.SoftCooldownSec = 60
	}
	if c.Pool.SoftCooldownMaxSec < c.Pool.SoftCooldownSec {
		c.Pool.SoftCooldownMaxSec = max(c.Pool.SoftCooldownSec*4, 3600)
	}
	if c.Pool.BreakerThreshold <= 0 {
		c.Pool.BreakerThreshold = 3
	}
	if c.Pool.BreakerCooldownSec <= 0 {
		c.Pool.BreakerCooldownSec = 900
	}
	if c.Pool.MaxRotate <= 0 {
		c.Pool.MaxRotate = 3
	}
	switch strings.ToLower(strings.TrimSpace(c.Pool.SelectionStrategy)) {
	case "weighted", "round_robin", "sequential":
		c.Pool.SelectionStrategy = strings.ToLower(strings.TrimSpace(c.Pool.SelectionStrategy))
	default:
		c.Pool.SelectionStrategy = "weighted"
	}

	if c.Schedule.QuotaRefreshMinutes <= 0 {
		c.Schedule.QuotaRefreshMinutes = 10
	}
	if c.Schedule.TokenRefreshCheckMinutes <= 0 {
		c.Schedule.TokenRefreshCheckMinutes = 1
	}
	if c.Schedule.TokenRefreshAdvanceMinute <= 0 {
		c.Schedule.TokenRefreshAdvanceMinute = 10
	}
	if c.Session.TTLMinutes <= 0 {
		c.Session.TTLMinutes = 30
	}
	if c.Models.Hidden == nil {
		c.Models.Hidden = []string{}
	}
	if c.Models.Allowed == nil {
		c.Models.Allowed = []string{}
	}
}

// AnchorPaths resolves relative auth_dir / data_dir against baseDir (normally the
// directory containing config.json). Absolute paths and an empty baseDir are left as-is.
func (c *Config) AnchorPaths(baseDir string) {
	if c == nil || baseDir == "" {
		return
	}
	if c.AuthDir != "" && !filepath.IsAbs(c.AuthDir) {
		c.AuthDir = filepath.Join(baseDir, c.AuthDir)
	}
	if c.DataDir != "" && !filepath.IsAbs(c.DataDir) {
		c.DataDir = filepath.Join(baseDir, c.DataDir)
	}
}

func (c *Config) StateFile() string         { return filepath.Join(c.DataDir, "state.json") }
func (c *Config) EncryptionKeyFile() string { return filepath.Join(c.DataDir, "encryption.key") }
func (c *Config) RequestLogDir() string     { return filepath.Join(c.DataDir, "request-logs") }
func (c *Config) APIKeysFile() string       { return filepath.Join(c.DataDir, "api-keys.json") }

// SaveFull validates a full JSON configuration document over defaults, writes it atomically,
// applies env overrides to the returned live Config, and reports fields that require restart.
func SaveFull(path string, raw []byte, oldCfg *Config) (*Config, []string, error) {
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF}))
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, nil, fmt.Errorf("invalid json: expected object")
	}
	diskCfg := Default()
	if err := json.Unmarshal(trimmed, diskCfg); err != nil {
		return nil, nil, fmt.Errorf("invalid json: %w", err)
	}
	diskCfg.normalize()
	if strings.TrimSpace(diskCfg.AdminKey) == "" && strings.TrimSpace(os.Getenv("AWSQUICK_ADMIN_KEY")) == "" {
		// Never persist an empty admin_key: it would be re-randomized on every
		// restart. Keep the current key when there is a valid one, otherwise generate once.
		switch {
		case oldCfg != nil && ValidAdminKey(oldCfg.AdminKey):
			diskCfg.AdminKey = oldCfg.AdminKey
		default:
			if prev, perr := LoadFileOnly(path); perr == nil && ValidAdminKey(prev.AdminKey) {
				diskCfg.AdminKey = prev.AdminKey
			} else {
				diskCfg.AdminKey = GenerateAdminKey()
			}
		}
	}

	outBytes, err := json.MarshalIndent(diskCfg, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	outBytes = append(outBytes, '\n')
	next := Default()
	if err := json.Unmarshal(outBytes, next); err != nil {
		return nil, nil, fmt.Errorf("validate saved config: %w", err)
	}
	next.applyEnv()
	next.normalize()
	if !ValidAPIKey(next.APIKey) {
		return nil, nil, fmt.Errorf("set a valid api_key in config or AWSQUICK_API_KEY")
	}
	if !ValidAdminKey(next.AdminKey) {
		return nil, nil, fmt.Errorf("set a valid admin_key in config or AWSQUICK_ADMIN_KEY")
	}
	if err := safefile.WriteAtomic(path, outBytes, 0o600); err != nil {
		return nil, nil, err
	}
	// The running config has auth_dir / data_dir anchored to the config directory;
	// anchor the new one the same way so unchanged relative paths do not diff.
	if filepath.IsAbs(path) {
		next.AnchorPaths(filepath.Dir(path))
	}

	return next, diffRestartFields(oldCfg, next), nil
}

func samePath(a, b string) bool {
	if a == b {
		return true
	}
	if a == "" || b == "" {
		return false
	}
	ca, cb := filepath.Clean(a), filepath.Clean(b)
	if filepath.Separator == '\\' {
		return strings.EqualFold(ca, cb)
	}
	return ca == cb
}

// DiffRestartFields reports configuration fields in next that differ from the
// process boot configuration bootCfg and therefore require a restart to take effect.
func DiffRestartFields(bootCfg, next *Config) []string {
	return diffRestartFields(bootCfg, next)
}

func diffRestartFields(oldCfg, next *Config) []string {
	if oldCfg == nil || next == nil {
		return nil
	}
	var restartFields []string
	if oldCfg.Listen != next.Listen {
		restartFields = append(restartFields, "listen")
	}
	if !samePath(oldCfg.AuthDir, next.AuthDir) {
		restartFields = append(restartFields, "auth_dir")
	}
	if !samePath(oldCfg.DataDir, next.DataDir) {
		restartFields = append(restartFields, "data_dir")
	}
	if oldCfg.Server.ReadTimeoutSeconds != next.Server.ReadTimeoutSeconds {
		restartFields = append(restartFields, "server.read_timeout_seconds")
	}
	if oldCfg.Server.ShutdownTimeoutSeconds != next.Server.ShutdownTimeoutSeconds {
		restartFields = append(restartFields, "server.shutdown_timeout_seconds")
	}
	if oldCfg.Server.MaxPayloadBytes != next.Server.MaxPayloadBytes {
		restartFields = append(restartFields, "server.max_payload_bytes")
	}
	if oldCfg.Server.MaxInflightPayloadBytes != next.Server.MaxInflightPayloadBytes {
		restartFields = append(restartFields, "server.max_inflight_payload_bytes")
	}
	return restartFields
}
