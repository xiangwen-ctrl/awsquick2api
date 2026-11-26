package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// clearEnv neutralizes AWSQUICK_* overrides that would otherwise leak from the host.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range envOverrideVars {
		t.Setenv(k, "")
	}
}

func writeJSON(t *testing.T, path string, v any) []byte {
	t.Helper()
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestNormalizeMaxFrameBytes(t *testing.T) {
	cases := map[int]int{
		0:       DefaultMaxFrameBytes,
		-1:      DefaultMaxFrameBytes,
		-100000: DefaultMaxFrameBytes,
		100:     MinMaxFrameBytes,
		8191:    MinMaxFrameBytes,
		8192:    8192,
		50000:   50000,
		63000:   63000,
	}
	for in, want := range cases {
		c := Default()
		c.Upstream.MaxFrameBytes = in
		c.normalize()
		if c.Upstream.MaxFrameBytes != want {
			t.Errorf("max_frame_bytes %d -> %d, want %d", in, c.Upstream.MaxFrameBytes, want)
		}
	}
}

func TestLoadFileOnlyRejectsZeroFrameBytes(t *testing.T) {
	clearEnv(t)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"upstream":{"max_frame_bytes":0}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFileOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Upstream.MaxFrameBytes != DefaultMaxFrameBytes {
		t.Fatalf("max_frame_bytes = %d, want %d", cfg.Upstream.MaxFrameBytes, DefaultMaxFrameBytes)
	}
}

func TestNormalizeDefaults(t *testing.T) {
	c := &Config{}
	c.normalize()
	if c.Listen != "127.0.0.1:8045" || c.AuthDir != "./auths" || c.DataDir != "./data" {
		t.Fatalf("unexpected defaults: listen=%q auth=%q data=%q", c.Listen, c.AuthDir, c.DataDir)
	}
	if c.Server.MaxPayloadBytes < 8<<20 || c.Server.MaxPayloadBytes > 512<<20 {
		t.Fatalf("max_payload_bytes out of range: %d", c.Server.MaxPayloadBytes)
	}
	if c.Pool.SelectionStrategy != "weighted" || c.Upstream.Stage != "prod" || c.Upstream.DefaultModel != "smart" {
		t.Fatalf("enum defaults not applied: %+v %+v", c.Pool, c.Upstream)
	}
}

func TestLoadOrCreateGeneratesIndependentKeys(t *testing.T) {
	clearEnv(t)
	path := filepath.Join(t.TempDir(), "config.json")
	cfg, created, err := LoadOrCreate(path)
	if err != nil || !created {
		t.Fatalf("LoadOrCreate: created=%v err=%v", created, err)
	}
	if !strings.HasPrefix(cfg.APIKey, "qk_") || !strings.HasPrefix(cfg.AdminKey, "qka_") || cfg.APIKey == cfg.AdminKey {
		t.Fatalf("bad generated keys: api=%q admin=%q", cfg.APIKey, cfg.AdminKey)
	}
	again, created, err := LoadOrCreate(path)
	if err != nil || created {
		t.Fatalf("second LoadOrCreate: created=%v err=%v", created, err)
	}
	if again.APIKey != cfg.APIKey || again.AdminKey != cfg.AdminKey {
		t.Fatal("keys changed between runs")
	}
}

// An existing config.json with an empty admin_key gets one generated exactly once (P2-22).
func TestLoadOrCreatePersistsGeneratedAdminKey(t *testing.T) {
	clearEnv(t)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"api_key":"qk_existing","admin_key":""}`), 0o600); err != nil {
		t.Fatal(err)
	}
	first, _, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first.AdminKey, "qka_") {
		t.Fatalf("admin_key not generated: %q", first.AdminKey)
	}
	disk, err := LoadFileOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	if disk.AdminKey != first.AdminKey || disk.APIKey != "qk_existing" {
		t.Fatalf("generated admin_key not persisted (disk=%q mem=%q api=%q)", disk.AdminKey, first.AdminKey, disk.APIKey)
	}
	second, _, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if second.AdminKey != first.AdminKey {
		t.Fatalf("admin_key re-randomized on restart: %q -> %q", first.AdminKey, second.AdminKey)
	}
}

func TestLoadOrCreateEnvAdminKeyNotPersisted(t *testing.T) {
	clearEnv(t)
	t.Setenv("AWSQUICK_ADMIN_KEY", "qka_from_env")
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"admin_key":""}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AdminKey != "qka_from_env" {
		t.Fatalf("env override not applied: %q", cfg.AdminKey)
	}
	disk, _ := LoadFileOnly(path)
	if disk.AdminKey != "" {
		t.Fatalf("env admin_key must not be written to disk, got %q", disk.AdminKey)
	}
}

// runningConfig mimics main.go: Load + anchor relative dirs to the config directory.
func runningConfig(t *testing.T, path string) *Config {
	t.Helper()
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AnchorPaths(filepath.Dir(path))
	return cfg
}

// Saving an unchanged config must not report auth_dir/data_dir as restart-required (P2-22).
func TestSaveFullNoSpuriousRestartFields(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	base := Default()
	base.APIKey, base.AdminKey = "qk_a", "qka_b"
	raw := writeJSON(t, path, base)

	old := runningConfig(t, path)
	next, restart, err := SaveFull(path, raw, old)
	if err != nil {
		t.Fatal(err)
	}
	if len(restart) != 0 {
		t.Fatalf("unchanged save reported restart_required=%v", restart)
	}
	if next.AuthDir != old.AuthDir || next.DataDir != old.DataDir {
		t.Fatalf("returned config not anchored like the running one: %q/%q vs %q/%q", next.AuthDir, next.DataDir, old.AuthDir, old.DataDir)
	}
	if !filepath.IsAbs(next.DataDir) {
		t.Fatalf("data_dir should be anchored to the config dir, got %q", next.DataDir)
	}

	// Equivalent spelling of the same relative dir is not a change either.
	base.AuthDir = "auths"
	raw = writeJSON(t, path, base)
	if _, restart, err = SaveFull(path, raw, old); err != nil || len(restart) != 0 {
		t.Fatalf("equivalent auth_dir reported restart_required=%v err=%v", restart, err)
	}
}

func TestSaveFullReportsRealRestartFields(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	base := Default()
	base.APIKey, base.AdminKey = "qk_a", "qka_b"
	writeJSON(t, path, base)
	old := runningConfig(t, path)

	changed := Default()
	changed.APIKey, changed.AdminKey = "qk_a", "qka_b"
	changed.Listen = "127.0.0.1:9000"
	changed.DataDir = "./data2"
	changed.Server.ShutdownTimeoutSeconds = 60
	changed.Upstream.MaxFrameBytes = 0 // corrected, not a restart field
	raw, _ := json.Marshal(changed)

	next, restart, err := SaveFull(path, raw, old)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"listen", "data_dir", "server.shutdown_timeout_seconds"} {
		if !slices.Contains(restart, want) {
			t.Errorf("restart_required=%v missing %q", restart, want)
		}
	}
	if slices.Contains(restart, "auth_dir") {
		t.Errorf("auth_dir unchanged but reported: %v", restart)
	}
	if next.Upstream.MaxFrameBytes != DefaultMaxFrameBytes {
		t.Errorf("saved max_frame_bytes = %d, want %d", next.Upstream.MaxFrameBytes, DefaultMaxFrameBytes)
	}
	disk, _ := LoadFileOnly(path)
	if disk.Upstream.MaxFrameBytes != DefaultMaxFrameBytes {
		t.Errorf("disk max_frame_bytes = %d, want corrected default", disk.Upstream.MaxFrameBytes)
	}
}

func TestSaveFullKeepsAdminKeyWhenBlank(t *testing.T) {
	clearEnv(t)
	path := filepath.Join(t.TempDir(), "config.json")
	base := Default()
	base.APIKey, base.AdminKey = "qk_a", "qka_keepme"
	writeJSON(t, path, base)
	old := runningConfig(t, path)

	blank := *base
	blank.AdminKey = ""
	raw, _ := json.Marshal(&blank)
	next, _, err := SaveFull(path, raw, old)
	if err != nil {
		t.Fatal(err)
	}
	if next.AdminKey != "qka_keepme" {
		t.Fatalf("admin_key = %q, want kept", next.AdminKey)
	}
	disk, _ := LoadFileOnly(path)
	if disk.AdminKey != "qka_keepme" {
		t.Fatalf("disk admin_key = %q, want kept", disk.AdminKey)
	}
}

func TestSaveFullRejectsInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	for _, raw := range []string{"", "[]", "not json", `{"listen":`} {
		if _, _, err := SaveFull(path, []byte(raw), nil); err == nil {
			t.Errorf("SaveFull(%q) accepted invalid input", raw)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("invalid input must not create the config file")
	}
}

func TestDiffRestartFieldsPathNormalization(t *testing.T) {
	a := Default()
	a.AuthDir = filepath.Join("base", "auths")
	b := Default()
	b.AuthDir = filepath.Join("base", ".", "auths") + string(filepath.Separator)
	if got := diffRestartFields(a, b); slices.Contains(got, "auth_dir") {
		t.Fatalf("cleaned-equal paths reported as changed: %v", got)
	}
	b.AuthDir = filepath.Join("base", "other")
	if got := diffRestartFields(a, b); !slices.Contains(got, "auth_dir") {
		t.Fatalf("changed auth_dir not reported: %v", got)
	}
	if diffRestartFields(nil, b) != nil {
		t.Fatal("nil old config must yield nil")
	}
}

func TestAnchorPaths(t *testing.T) {
	base := t.TempDir()
	c := Default()
	c.AnchorPaths(base)
	if c.AuthDir != filepath.Join(base, "auths") || c.DataDir != filepath.Join(base, "data") {
		t.Fatalf("relative dirs not anchored: %q %q", c.AuthDir, c.DataDir)
	}
	abs := filepath.Join(base, "abs")
	c.AuthDir = abs
	c.AnchorPaths(filepath.Join(base, "elsewhere"))
	if c.AuthDir != abs {
		t.Fatalf("absolute dir rewritten: %q", c.AuthDir)
	}
	c2 := Default()
	c2.AnchorPaths("")
	if c2.AuthDir != "./auths" {
		t.Fatal("empty base must be a no-op")
	}
}

func TestSnapshotFromConfigLowercasesModelSets(t *testing.T) {
	c := Default()
	c.Models.Hidden = []string{" Amazon-Fast ", ""}
	c.Models.Allowed = []string{"AMAZON-SMART"}
	c.Thinking.ModelOverrides = map[string]string{" Amazon-Smart ": " HIGH "}
	s := SnapshotFromConfig(c)
	if !s.HiddenModels["amazon-fast"] || len(s.HiddenModels) != 1 {
		t.Fatalf("hidden = %v", s.HiddenModels)
	}
	if !s.AllowlistEnabled || !s.AllowedModels["amazon-smart"] {
		t.Fatalf("allowed = %v", s.AllowedModels)
	}
	if s.Thinking.ModelOverrides["amazon-smart"] != "high" {
		t.Fatalf("overrides = %v", s.Thinking.ModelOverrides)
	}
}

func TestTrustedHostsConfigAndEnvOverride(t *testing.T) {
	clearEnv(t)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"server":{"trusted_hosts":[" panel.example.com ","PANEL.EXAMPLE.COM","","gw.internal:8443"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"panel.example.com", "gw.internal:8443"}
	if !slices.Equal(cfg.Server.TrustedHosts, want) {
		t.Fatalf("TrustedHosts = %v, want %v", cfg.Server.TrustedHosts, want)
	}
	snap := SnapshotFromConfig(cfg)
	if !slices.Equal(snap.TrustedHosts, want) {
		t.Fatalf("Snapshot.TrustedHosts = %v, want %v", snap.TrustedHosts, want)
	}

	// Env override splits comma-separated list, trims, deduplicates, and shows in ActiveEnvOverrides.
	t.Setenv("AWSQUICK_TRUSTED_HOSTS", " a.example.com , b.example.com, A.EXAMPLE.COM , ")
	cfgEnv, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	wantEnv := []string{"a.example.com", "b.example.com"}
	if !slices.Equal(cfgEnv.Server.TrustedHosts, wantEnv) {
		t.Fatalf("env TrustedHosts = %v, want %v", cfgEnv.Server.TrustedHosts, wantEnv)
	}
	if !slices.Contains(ActiveEnvOverrides(), "AWSQUICK_TRUSTED_HOSTS") {
		t.Fatalf("AWSQUICK_TRUSTED_HOSTS missing from ActiveEnvOverrides: %v", ActiveEnvOverrides())
	}
	// Changing trusted_hosts is hot-reloadable and must not trigger restart_required.
	if restart := DiffRestartFields(cfg, cfgEnv); len(restart) != 0 {
		t.Fatalf("trusted_hosts change must not require restart, got %v", restart)
	}
}

// P2-7: multiple hot-reload saves must compute restart_required against the boot config.
func TestDiffRestartFieldsPersistsAcrossMultipleSaves(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	base := Default()
	base.APIKey, base.AdminKey = "qk_a", "qka_b"
	writeJSON(t, path, base)

	bootCfg := runningConfig(t, path)
	currentCfg := bootCfg

	// Save 1: change restart-required listen address.
	s1 := *base
	s1.Listen = "127.0.0.1:9999"
	raw1, _ := json.Marshal(&s1)
	next1, _, err := SaveFull(path, raw1, currentCfg)
	if err != nil {
		t.Fatal(err)
	}
	currentCfg = next1
	if r1 := DiffRestartFields(bootCfg, next1); !slices.Equal(r1, []string{"listen"}) {
		t.Fatalf("save 1 restart_required = %v, want [listen]", r1)
	}

	// Save 2: change only a hot-reloadable field; listen still differs from bootCfg.
	s2 := s1
	s2.Features.ClaudeAliases = false
	raw2, _ := json.Marshal(&s2)
	next2, _, err := SaveFull(path, raw2, currentCfg)
	if err != nil {
		t.Fatal(err)
	}
	currentCfg = next2
	if r2 := DiffRestartFields(bootCfg, next2); !slices.Equal(r2, []string{"listen"}) {
		t.Fatalf("save 2 restart_required = %v, want [listen]", r2)
	}

	// Save 3: revert listen back to boot value; restart_required clears.
	s3 := s2
	s3.Listen = bootCfg.Listen
	raw3, _ := json.Marshal(&s3)
	next3, _, err := SaveFull(path, raw3, currentCfg)
	if err != nil {
		t.Fatal(err)
	}
	if r3 := DiffRestartFields(bootCfg, next3); len(r3) != 0 {
		t.Fatalf("save 3 restart_required = %v, want empty", r3)
	}
}

func TestInvalidEffectiveKeyLeavesSavedConfigurationIntact(t *testing.T) {
	clearEnv(t)
	path := filepath.Join(t.TempDir(), "config.json")
	base := Default()
	base.APIKey = "qk_before_save"
	writeJSON(t, path, base)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	invalid := []byte(`{"api_key":"replace_with_your_api_key"}`)
	if _, _, err := SaveFull(path, invalid, base); err == nil {
		t.Fatal("accepted the example inference key")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(original) {
		t.Fatalf("rejected save changed the file, read error %v", err)
	}
	t.Setenv("AWSQUICK_API_KEY", "qk_from_environment")
	next, _, err := SaveFull(path, invalid, base)
	if err != nil || next.APIKey != "qk_from_environment" {
		t.Fatalf("valid environment override did not apply: %v", err)
	}
}

func TestThreadReuseRequiresNewExplicitSetting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	for _, tc := range []struct {
		body string
		want bool
	}{
		{`{}`, false},
		{`{"upstream":{"stateful":true}}`, false},
		{`{"upstream":{"single_client_thread_reuse":true}}`, true},
	} {
		if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadFileOnly(path)
		if err != nil || cfg.Upstream.Stateful != tc.want {
			t.Fatalf("unexpected reuse setting for %s: %v", tc.body, err)
		}
	}
}

func TestAdminKeyValidationTrimAndInflightPayloadFloor(t *testing.T) {
	clearEnv(t)
	if ValidAdminKey("") || ValidAdminKey("  ") || ValidAdminKey(ExampleAdminKey) {
		t.Fatal("empty or example admin_key must be invalid")
	}
	if !ValidAdminKey("qka_custom_secret") {
		t.Fatal("custom admin_key should be valid")
	}

	path := filepath.Join(t.TempDir(), "config.json")
	base := Default()
	base.APIKey = "qk_valid_key"
	base.AdminKey = "qka_valid_key"
	writeJSON(t, path, base)

	// Example admin_key placeholder must be rejected without touching disk.
	if _, _, err := SaveFull(path, []byte(`{"api_key":"qk_valid_key","admin_key":"replace_with_your_admin_key"}`), base); err == nil {
		t.Fatal("SaveFull accepted example admin_key placeholder")
	}

	// Whitespace around admin_key is trimmed and small max_inflight_payload_bytes is clamped to 8 MiB.
	next, _, err := SaveFull(path, []byte(`{"api_key":" qk_valid_key ","admin_key":" qka_trimmed\n","server":{"max_inflight_payload_bytes":64}}`), base)
	if err != nil {
		t.Fatalf("SaveFull failed: %v", err)
	}
	if next.AdminKey != "qka_trimmed" {
		t.Fatalf("AdminKey = %q, want %q", next.AdminKey, "qka_trimmed")
	}
	if next.Server.MaxInflightPayloadBytes != 8<<20 {
		t.Fatalf("MaxInflightPayloadBytes = %d, want %d", next.Server.MaxInflightPayloadBytes, 8<<20)
	}
}
