package panel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"awsquick2api/internal/auth"
	"awsquick2api/internal/config"
	"awsquick2api/internal/pool"
	"awsquick2api/internal/reqlog"
	"awsquick2api/internal/upstream"
)

func TestPanelAuthSeparationAndEncryptedExportImport(t *testing.T) {
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auths")
	vault, err := auth.OpenOrCreateVault(filepath.Join(dir, "encryption.key"), "")
	if err != nil {
		t.Fatalf("OpenOrCreateVault: %v", err)
	}

	cfg := config.Default()
	cfg.APIKey = "qk_inference_only_key"
	cfg.AdminKey = "qka_panel_admin_secret"
	live := config.NewLiveHolder(cfg)

	p := pool.New(pool.Config{})
	acct := &auth.Account{
		UID:          "soc_bob_1111",
		Email:        "bob@example.com",
		Provider:     auth.ProviderSocial,
		Stage:        "prod",
		Region:       "us-east-1",
		TenantURL:    "https://cell001.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev",
		AccessToken:  "acc_bob_secret_value",
		RefreshToken: "ref_bob_secret_value",
		ExpiresAt:    time.Now().Add(time.Hour).UnixMilli(),
		DeviceID:     auth.NewUUID(),
	}
	p.AddOrUpdate(acct)
	if err := auth.SaveAccount(authDir, vault, acct); err != nil {
		t.Fatalf("SaveAccount: %v", err)
	}

	pn := New(Config{
		Pool:     p,
		Vault:    vault,
		Upstream: upstream.NewClient(cfg.Upstream, nil),
		ReqLog:   reqlog.New("", false),
		Live:     live,
		AuthDir:  authDir,
		Version:  "0.1.0",
	})

	// 1. Inference api_key MUST be rejected on /panel/api/* (401).
	req := httptest.NewRequest(http.MethodGet, "/panel/api/overview", nil)
	req.Header.Set("Authorization", "Bearer qk_inference_only_key")
	w := httptest.NewRecorder()
	pn.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when using api_key on panel, got %d", w.Code)
	}

	// 2. Reject cross-origin requests even with admin_key.
	req = httptest.NewRequest(http.MethodGet, "/panel/api/overview", nil)
	req.Header.Set("Authorization", "Bearer qka_panel_admin_secret")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	w = httptest.NewRecorder()
	pn.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 cross-site, got %d", w.Code)
	}

	// 3. Overview succeeds with same-origin admin_key.
	req = httptest.NewRequest(http.MethodGet, "/panel/api/overview", nil)
	req.Header.Set("Authorization", "Bearer qka_panel_admin_secret")
	w = httptest.NewRecorder()
	pn.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"version":"0.1.0"`) {
		t.Fatalf("overview failed: %d %s", w.Code, w.Body.String())
	}

	// 4. Unencrypted JSON import MUST be rejected (400).
	plainImp := httptest.NewRequest(http.MethodPost, "/panel/api/accounts/import",
		strings.NewReader(`{"payload":{"uid":"soc_plain","access_token":"tok"}}`))
	plainImp.Header.Set("Authorization", "Bearer qka_panel_admin_secret")
	plainImp.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	pn.ServeHTTP(w, plainImp)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on unencrypted import, got %d %s", w.Code, w.Body.String())
	}

	// 5. Encrypted export -> delete -> encrypted import round-trip, verifying disk encryption.
	expReq := httptest.NewRequest(http.MethodPost, "/panel/api/accounts/export-encrypted", strings.NewReader(`{"passphrase":"my-long-passphrase-123"}`))
	expReq.Header.Set("Authorization", "Bearer qka_panel_admin_secret")
	expReq.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	pn.ServeHTTP(w, expReq)
	if w.Code != http.StatusOK {
		t.Fatalf("export-encrypted failed: %d %s", w.Code, w.Body.String())
	}
	sealed := w.Body.Bytes()

	delReq := httptest.NewRequest(http.MethodDelete, "/panel/api/accounts/soc_bob_1111", nil)
	delReq.Header.Set("Authorization", "Bearer qka_panel_admin_secret")
	w = httptest.NewRecorder()
	pn.ServeHTTP(w, delReq)
	if w.Code != http.StatusOK || len(p.Snapshot()) != 0 {
		t.Fatalf("delete failed: %d", w.Code)
	}

	impBody, _ := json.Marshal(map[string]any{
		"payload":    json.RawMessage(sealed),
		"passphrase": "my-long-passphrase-123",
		"overwrite":  false,
	})
	impReq := httptest.NewRequest(http.MethodPost, "/panel/api/accounts/import", bytes.NewReader(impBody))
	impReq.Header.Set("Authorization", "Bearer qka_panel_admin_secret")
	impReq.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	pn.ServeHTTP(w, impReq)
	if w.Code != http.StatusOK || len(p.Snapshot()) != 1 {
		t.Fatalf("encrypted import failed: %d %s", w.Code, w.Body.String())
	}

	// Verify imported account on disk is encrypted at rest.
	diskRaw, err := os.ReadFile(filepath.Join(authDir, "soc_bob_1111.json"))
	if err != nil {
		t.Fatalf("read disk account: %v", err)
	}
	if !auth.IsLocalEncryptedEnvelope(diskRaw) || strings.Contains(string(diskRaw), "acc_bob_secret_value") {
		t.Fatalf("imported account file is not encrypted at rest: %s", string(diskRaw))
	}
}

// --- hardening tests: Host guard, admin_key rate limit, rename sync, import validation ---

const testAdminKey = "qka_panel_admin_secret"

// memConfig is an in-memory stand-in for config.json used by LoadConfig/SaveConfig.
type memConfig struct {
	mu sync.Mutex
	c  *config.Config
}

func (m *memConfig) load() (*config.Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	raw, err := json.Marshal(m.c)
	if err != nil {
		return nil, err
	}
	var out config.Config
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (m *memConfig) save(raw []byte) (SaveConfigResult, error) {
	var c config.Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return SaveConfigResult{}, err
	}
	m.mu.Lock()
	m.c = &c
	m.mu.Unlock()
	return SaveConfigResult{}, nil
}

func (m *memConfig) get() *config.Config {
	c, _ := m.load()
	return c
}

func newHardeningPanel(t *testing.T, mutate func(*Config)) (*Panel, *memConfig, *pool.Pool) {
	t.Helper()
	cfg := config.Default()
	cfg.APIKey = "qk_inference_only_key"
	cfg.AdminKey = testAdminKey
	mc := &memConfig{c: cfg}
	p := pool.New(pool.Config{})
	pc := Config{
		Pool:       p,
		Upstream:   upstream.NewClient(cfg.Upstream, nil),
		ReqLog:     reqlog.New("", false),
		Live:       config.NewLiveHolder(cfg),
		Version:    "0.1.0",
		LoadConfig: mc.load,
		SaveConfig: mc.save,
	}
	if mutate != nil {
		mutate(&pc)
	}
	return New(pc), mc, p
}

func doPanelReq(pn *Panel, method, path, host, remote, key string, body any) *httptest.ResponseRecorder {
	var req *http.Request
	if body != nil {
		raw, _ := json.Marshal(body)
		req = httptest.NewRequest(method, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if host != "" {
		req.Host = host
	}
	if remote != "" {
		req.RemoteAddr = remote
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	w := httptest.NewRecorder()
	pn.ServeHTTP(w, req)
	return w
}

func TestPanelHostHeaderGuard(t *testing.T) {
	// Loopback listen resolved from LoadConfig fallback (config.Default listen = 127.0.0.1:8045).
	pn, _, _ := newHardeningPanel(t, nil)
	cases := []struct {
		host string
		want int
	}{
		{"127.0.0.1:8045", http.StatusOK},
		{"localhost:8045", http.StatusOK},
		{"LOCALHOST", http.StatusOK},
		{"[::1]:8045", http.StatusOK},
		{"evil.example.com", http.StatusForbidden},
		{"evil.example.com:8045", http.StatusForbidden},
		{"127.0.0.1.evil.example.com", http.StatusForbidden},
	}
	for _, c := range cases {
		w := doPanelReq(pn, http.MethodGet, "/panel/api/overview", c.host, "", testAdminKey, nil)
		if w.Code != c.want {
			t.Fatalf("host %q: want %d, got %d %s", c.host, c.want, w.Code, w.Body.String())
		}
	}
	// Static assets are guarded too (a rebinding page could read the SPA otherwise).
	if w := doPanelReq(pn, http.MethodGet, "/panel/", "rebind.example.com", "", "", nil); w.Code != http.StatusForbidden {
		t.Fatalf("static asset with foreign host: want 403, got %d", w.Code)
	}

	// Explicit loopback listen + TrustedHosts.
	pn2, _, _ := newHardeningPanel(t, func(c *Config) {
		c.ListenAddr = "localhost:9000"
		c.TrustedHosts = []string{"panel.example.com"}
	})
	if w := doPanelReq(pn2, http.MethodGet, "/panel/api/overview", "panel.example.com", "", testAdminKey, nil); w.Code != http.StatusOK {
		t.Fatalf("trusted host: want 200, got %d", w.Code)
	}
	if w := doPanelReq(pn2, http.MethodGet, "/panel/api/overview", "other.example.com", "", testAdminKey, nil); w.Code != http.StatusForbidden {
		t.Fatalf("untrusted host: want 403, got %d", w.Code)
	}

	// Non-loopback bind: Host guard disabled (network-level controls apply).
	pn3, _, _ := newHardeningPanel(t, func(c *Config) { c.ListenAddr = "0.0.0.0:8045" })
	if w := doPanelReq(pn3, http.MethodGet, "/panel/api/overview", "gw.example.com", "", testAdminKey, nil); w.Code != http.StatusOK {
		t.Fatalf("wildcard bind: want 200, got %d", w.Code)
	}
}

func TestPanelAdminKeyRateLimit(t *testing.T) {
	pn, _, _ := newHardeningPanel(t, nil)
	host := "127.0.0.1:8045"
	attacker := "10.0.0.9:5555"
	for i := 0; i < authFailLimit; i++ {
		if w := doPanelReq(pn, http.MethodGet, "/panel/api/overview", host, attacker, "wrong-key", nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: want 401, got %d", i, w.Code)
		}
	}
	// Budget exhausted: even the correct key is refused for this IP.
	w := doPanelReq(pn, http.MethodGet, "/panel/api/overview", host, attacker, testAdminKey, nil)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("want 429 with Retry-After, got %d %q", w.Code, w.Header().Get("Retry-After"))
	}
	// Another source IP is unaffected.
	if w := doPanelReq(pn, http.MethodGet, "/panel/api/overview", host, "10.0.0.10:5555", testAdminKey, nil); w.Code != http.StatusOK {
		t.Fatalf("other ip: want 200, got %d", w.Code)
	}
	// Window expiry unblocks.
	base := time.Now()
	pn.authLim.mu.Lock()
	pn.authLim.now = func() time.Time { return base.Add(authFailWindow + time.Second) }
	pn.authLim.mu.Unlock()
	if w := doPanelReq(pn, http.MethodGet, "/panel/api/overview", host, attacker, testAdminKey, nil); w.Code != http.StatusOK {
		t.Fatalf("after window: want 200, got %d", w.Code)
	}
	// Success resets the counter.
	pn.authLim.mu.Lock()
	pn.authLim.now = time.Now
	pn.authLim.mu.Unlock()
	doPanelReq(pn, http.MethodGet, "/panel/api/overview", host, attacker, "wrong-key", nil)
	doPanelReq(pn, http.MethodGet, "/panel/api/overview", host, attacker, testAdminKey, nil)
	if pn.authLim.size() != 0 {
		t.Fatalf("expected limiter reset after success, size=%d", pn.authLim.size())
	}

	// Memory stays bounded under a spray of distinct IPs.
	oldMax := authLimiterMaxKeys
	authLimiterMaxKeys = 64
	defer func() { authLimiterMaxKeys = oldMax }()
	lim := newAuthLimiter()
	for i := 0; i < 1000; i++ {
		lim.fail(fmt.Sprintf("10.1.%d.%d", i/250, i%250))
	}
	if n := lim.size(); n > authLimiterMaxKeys {
		t.Fatalf("limiter grew unbounded: %d > %d", n, authLimiterMaxKeys)
	}
}

func TestPanelStrictPrivacyToggle(t *testing.T) {
	pn, mc, _ := newHardeningPanel(t, nil)
	host := "127.0.0.1:8045"
	w := doPanelReq(pn, http.MethodGet, "/panel/api/overview", host, "", testAdminKey, nil)
	if !strings.Contains(w.Body.String(), `"strict_privacy_dlp":true`) {
		t.Fatalf("overview should expose strict_privacy_dlp: %s", w.Body.String())
	}
	w = doPanelReq(pn, http.MethodPatch, "/panel/api/features/strict-privacy-dlp", host, "", testAdminKey, map[string]any{"enabled": false})
	if w.Code != http.StatusOK || mc.get().Features.StrictPrivacyDLP {
		t.Fatalf("disable strict_privacy_dlp failed: %d %s", w.Code, w.Body.String())
	}
	if w = doPanelReq(pn, http.MethodPatch, "/panel/api/features/strict-privacy-dlp", host, "", testAdminKey, map[string]any{}); w.Code != http.StatusBadRequest {
		t.Fatalf("missing enabled: want 400, got %d", w.Code)
	}
}

func TestPanelModelRenameSyncsConfig(t *testing.T) {
	pn, mc, _ := newHardeningPanel(t, nil)
	cat := pn.cfg.Upstream.GetCatalog()
	if cat == nil || len(cat.Specs) == 0 {
		t.Fatal("default catalog empty")
	}
	spec := cat.Specs[0]
	oldID := spec.ID
	newID := "my-renamed-model"

	mc.mu.Lock()
	mc.c.Models.Hidden = []string{oldID, strings.ToUpper(oldID) + "-high", oldID + "-mini", "unrelated"}
	mc.c.Models.Allowed = []string{oldID + "[1m]", "unrelated"}
	mc.c.Thinking.ModelOverrides = map[string]string{oldID: "high", oldID + "-low": "low", "unrelated": "medium"}
	mc.mu.Unlock()

	w := doPanelReq(pn, http.MethodPut, "/panel/api/models/"+spec.Slot+"/rename", "127.0.0.1:8045", "", testAdminKey,
		map[string]any{"id": newID, "display": "Renamed"})
	if w.Code != http.StatusOK {
		t.Fatalf("rename failed: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"config_migrated":5`) {
		t.Fatalf("expected 5 migrated refs: %s", w.Body.String())
	}
	got := mc.get()
	wantHidden := []string{newID, newID + "-high", oldID + "-mini", "unrelated"}
	if strings.Join(got.Models.Hidden, ",") != strings.Join(wantHidden, ",") {
		t.Fatalf("hidden not migrated: %v", got.Models.Hidden)
	}
	if strings.Join(got.Models.Allowed, ",") != newID+"[1m],unrelated" {
		t.Fatalf("allowed not migrated: %v", got.Models.Allowed)
	}
	ov := got.Thinking.ModelOverrides
	if ov[newID] != "high" || ov[newID+"-low"] != "low" || ov["unrelated"] != "medium" || len(ov) != 3 {
		t.Fatalf("model_overrides not migrated: %v", ov)
	}
	if _, stale := ov[oldID]; stale {
		t.Fatalf("old override key still present: %v", ov)
	}
}

func TestValidateImportedEndpoints(t *testing.T) {
	good := func() *auth.Account {
		return &auth.Account{
			Region:        "us-east-1",
			TenantURL:     "https://cell001.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev",
			WSHost:        "cell001.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev",
			WSPath:        auth.DefaultWSPath,
			TokenEndpoint: "https://oidc.us-east-1.amazonaws.com/token",
		}
	}
	if err := validateImportedEndpoints(good()); err != nil {
		t.Fatalf("good account rejected: %v", err)
	}
	gw := good()
	gw.WSHost = "wss://cell001.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev:443"
	gw.WSPath = auth.GatewayWSPath
	if err := validateImportedEndpoints(gw); err != nil {
		t.Fatalf("wss host rejected: %v", err)
	}
	bad := map[string]func(a *auth.Account){
		"ws plaintext":     func(a *auth.Account) { a.WSHost = "ws://cell001.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev" },
		"http ws host":     func(a *auth.Account) { a.WSHost = "http://quick.aws.com" },
		"foreign ws host":  func(a *auth.Account) { a.WSHost = "evil.example.com" },
		"ws host port":     func(a *auth.Account) { a.WSHost = "quick.aws.com:8443" },
		"ws host userinfo": func(a *auth.Account) { a.WSHost = "user@quick.aws.com" },
		"ws host path":     func(a *auth.Account) { a.WSHost = "quick.aws.com/x" },
		"ws path absolute": func(a *auth.Account) { a.WSPath = "wss://evil.example.com/stream" },
		"ws path dotdot":   func(a *auth.Account) { a.WSPath = "/streaming/../x" },
		"ws path scheme":   func(a *auth.Account) { a.WSPath = "//evil.example.com/x" },
		"ws path query":    func(a *auth.Account) { a.WSPath = "/x?y=1" },
		"tenant foreign":   func(a *auth.Account) { a.TenantURL = "https://evil.example.com" },
		"tenant http":      func(a *auth.Account) { a.TenantURL = "http://quick.aws.com" },
		"token endpoint":   func(a *auth.Account) { a.TokenEndpoint = "https://attacker.example.net/token" },
		"issuer localhost": func(a *auth.Account) { a.IssuerURL = "http://127.0.0.1:9999" },
		"bad region":       func(a *auth.Account) { a.Region = "us-east-1.evil" },
	}
	for name, mut := range bad {
		a := good()
		mut(a)
		if err := validateImportedEndpoints(a); err == nil {
			t.Fatalf("%s: expected rejection", name)
		}
	}
}

func TestPanelImportRejectsUntrustedEndpointsAndNotifies(t *testing.T) {
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auths")
	vault, err := auth.OpenOrCreateVault(filepath.Join(dir, "encryption.key"), "")
	if err != nil {
		t.Fatalf("OpenOrCreateVault: %v", err)
	}
	notified := make(chan []string, 1)
	pn, _, p := newHardeningPanel(t, func(c *Config) {
		c.Vault = vault
		c.AuthDir = authDir
		c.OnAccountsImported = func(uids []string) { notified <- uids }
	})

	mk := func(uid string) *auth.Account {
		return &auth.Account{
			UID:          uid,
			Email:        uid + "@example.com",
			Provider:     auth.ProviderSocial,
			Stage:        "prod",
			Region:       "us-east-1",
			TenantURL:    "https://cell001.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev",
			AccessToken:  "acc_" + uid,
			RefreshToken: "ref_" + uid,
			ExpiresAt:    time.Now().Add(time.Hour).UnixMilli(),
			DeviceID:     auth.NewUUID(),
		}
	}
	okAcct := mk("soc_good_1")
	wsDowngrade := mk("soc_bad_ws")
	wsDowngrade.WSHost = "ws://evil.example.com"
	foreignTenant := mk("soc_bad_tenant")
	foreignTenant.TenantURL = "https://evil.example.com"
	badPath := mk("soc_bad_path")
	badPath.WSPath = "/../../etc"

	sealed, err := auth.EncryptAccounts([]*auth.Account{okAcct, wsDowngrade, foreignTenant, badPath}, "my-long-passphrase-123")
	if err != nil {
		t.Fatalf("EncryptAccounts: %v", err)
	}
	w := doPanelReq(pn, http.MethodPost, "/panel/api/accounts/import", "127.0.0.1:8045", "", testAdminKey, map[string]any{
		"payload":    json.RawMessage(sealed),
		"passphrase": "my-long-passphrase-123",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("import failed: %d %s", w.Code, w.Body.String())
	}
	var res struct {
		Imported int      `json:"imported"`
		Errors   []string `json:"errors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Imported != 1 || len(res.Errors) != 3 {
		t.Fatalf("want 1 imported / 3 rejected, got %d / %v", res.Imported, res.Errors)
	}
	for _, uid := range []string{"soc_bad_ws", "soc_bad_tenant", "soc_bad_path"} {
		if p.AuthByUID(uid) != nil {
			t.Fatalf("%s should not be in pool", uid)
		}
		if _, err := os.Stat(filepath.Join(authDir, uid+".json")); err == nil {
			t.Fatalf("%s should not be persisted", uid)
		}
	}
	select {
	case uids := <-notified:
		if len(uids) != 1 || uids[0] != "soc_good_1" {
			t.Fatalf("OnAccountsImported got %v", uids)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("OnAccountsImported not called")
	}
}

func TestPanelTrustedHostsLiveReload(t *testing.T) {
	// 1. LiveHolder fallback when TrustedHosts is empty on Config.
	pn, _, _ := newHardeningPanel(t, func(c *Config) {
		c.ListenAddr = "127.0.0.1:8045"
	})
	if w := doPanelReq(pn, http.MethodGet, "/panel/api/overview", "proxy1.example.com", "", testAdminKey, nil); w.Code != http.StatusForbidden {
		t.Fatalf("before reload: want 403, got %d", w.Code)
	}
	nextCfg := config.Default()
	nextCfg.AdminKey = testAdminKey
	nextCfg.Server.TrustedHosts = []string{"proxy1.example.com"}
	pn.cfg.Live.UpdateFrom(nextCfg)
	if w := doPanelReq(pn, http.MethodGet, "/panel/api/overview", "proxy1.example.com", "", testAdminKey, nil); w.Code != http.StatusOK {
		t.Fatalf("after Live reload: want 200, got %d", w.Code)
	}

	// 2. Explicit UpdateTrustedHosts replaces previous list (adding new & revoking removed host).
	pn.UpdateTrustedHosts([]string{"proxy2.example.com:8443"})
	if w := doPanelReq(pn, http.MethodGet, "/panel/api/overview", "proxy2.example.com", "", testAdminKey, nil); w.Code != http.StatusOK {
		t.Fatalf("new trusted host: want 200, got %d", w.Code)
	}
	if w := doPanelReq(pn, http.MethodGet, "/panel/api/overview", "proxy1.example.com", "", testAdminKey, nil); w.Code != http.StatusForbidden {
		t.Fatalf("removed trusted host must be rejected: want 403, got %d", w.Code)
	}
}

func TestPanelModelRenameOffSuffixAndCaseInsensitiveDedupe(t *testing.T) {
	pn, mc, _ := newHardeningPanel(t, nil)
	cat := pn.cfg.Upstream.GetCatalog()
	spec := cat.Specs[0]
	oldID := spec.ID
	newID := "my-renamed-model"

	mc.mu.Lock()
	mc.c.Models.Hidden = []string{oldID + "-off", oldID + "-off[1m]", "MY-RENAMED-MODEL"}
	mc.c.Models.Allowed = []string{oldID, "my-renamed-model"}
	mc.c.Thinking.ModelOverrides = map[string]string{
		oldID + "-off":     "off",
		oldID:              "high",
		"MY-RENAMED-MODEL": "low", // pre-existing target key with different case must win & dedupe
	}
	mc.mu.Unlock()

	w := doPanelReq(pn, http.MethodPut, "/panel/api/models/"+spec.Slot+"/rename", "127.0.0.1:8045", "", testAdminKey,
		map[string]any{"id": newID, "display": "Renamed"})
	if w.Code != http.StatusOK {
		t.Fatalf("rename failed: %d %s", w.Code, w.Body.String())
	}
	got := mc.get()
	wantHidden := []string{newID + "-off", newID + "-off[1m]", "MY-RENAMED-MODEL"}
	if strings.Join(got.Models.Hidden, ",") != strings.Join(wantHidden, ",") {
		t.Fatalf("hidden mismatch: got %v, want %v", got.Models.Hidden, wantHidden)
	}
	if len(got.Models.Allowed) != 1 || !strings.EqualFold(got.Models.Allowed[0], newID) {
		t.Fatalf("allowed not deduplicated: %v", got.Models.Allowed)
	}
	if len(got.Thinking.ModelOverrides) != 2 {
		t.Fatalf("model_overrides case-insensitive dedupe failed: %v", got.Thinking.ModelOverrides)
	}
	if got.Thinking.ModelOverrides[newID+"-off"] != "off" {
		t.Fatalf("-off suffix not migrated in overrides: %v", got.Thinking.ModelOverrides)
	}
	if got.Thinking.ModelOverrides["MY-RENAMED-MODEL"] != "low" {
		t.Fatalf("existing target override should be preserved: %v", got.Thinking.ModelOverrides)
	}
}

func TestAuthLimiterDeterministicOldestEviction(t *testing.T) {
	oldMax := authLimiterMaxKeys
	authLimiterMaxKeys = 3
	defer func() { authLimiterMaxKeys = oldMax }()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	lim := newAuthLimiter()
	lim.now = func() time.Time { return now }

	lim.fail("10.0.0.1")
	now = now.Add(time.Second)
	lim.fail("10.0.0.2")
	now = now.Add(time.Second)
	lim.fail("10.0.0.3")
	now = now.Add(time.Second)
	// Adding a 4th key must deterministically evict the oldest entry (10.0.0.1).
	lim.fail("10.0.0.4")

	lim.mu.Lock()
	_, has1 := lim.m["10.0.0.1"]
	_, has2 := lim.m["10.0.0.2"]
	_, has3 := lim.m["10.0.0.3"]
	_, has4 := lim.m["10.0.0.4"]
	lim.mu.Unlock()
	if has1 || !has2 || !has3 || !has4 {
		t.Fatalf("expected oldest 10.0.0.1 evicted and 2/3/4 kept, got 1=%v 2=%v 3=%v 4=%v", has1, has2, has3, has4)
	}
}

func TestPanelModelVisibilityToggleWithAllowlist(t *testing.T) {
	pn, mc, _ := newHardeningPanel(t, nil)
	host := "127.0.0.1:8045"

	mc.mu.Lock()
	mc.c.Models.Allowed = []string{"amazon-fast"}
	mc.c.Models.Hidden = nil
	mc.mu.Unlock()

	// Showing amazon-smart while allowlist is active must add it to models.allowed.
	w := doPanelReq(pn, http.MethodPatch, "/panel/api/models/amazon-smart", host, "", testAdminKey, map[string]any{"visible": true})
	if w.Code != http.StatusOK {
		t.Fatalf("show amazon-smart: %d %s", w.Code, w.Body.String())
	}
	got := mc.get()
	if strings.Join(got.Models.Allowed, ",") != "amazon-fast,amazon-smart" {
		t.Fatalf("allowed after show = %v", got.Models.Allowed)
	}

	// Hiding amazon-smart when 2 models are allowed removes it from allowed and adds to hidden.
	w = doPanelReq(pn, http.MethodPatch, "/panel/api/models/amazon-smart", host, "", testAdminKey, map[string]any{"visible": false})
	if w.Code != http.StatusOK {
		t.Fatalf("hide amazon-smart: %d %s", w.Code, w.Body.String())
	}
	got = mc.get()
	if strings.Join(got.Models.Allowed, ",") != "amazon-fast" || strings.Join(got.Models.Hidden, ",") != "amazon-smart" {
		t.Fatalf("after hide smart: allowed=%v hidden=%v", got.Models.Allowed, got.Models.Hidden)
	}

	// Hiding the last allowed model must NOT empty models.allowed (which would disable allowlist).
	w = doPanelReq(pn, http.MethodPatch, "/panel/api/models/amazon-fast", host, "", testAdminKey, map[string]any{"visible": false})
	if w.Code != http.StatusOK {
		t.Fatalf("hide amazon-fast: %d %s", w.Code, w.Body.String())
	}
	got = mc.get()
	if len(got.Models.Allowed) != 1 || got.Models.Allowed[0] != "amazon-fast" {
		t.Fatalf("hiding sole allowed model must keep allowlist active: allowed=%v", got.Models.Allowed)
	}
	if !strings.Contains(strings.Join(got.Models.Hidden, ","), "amazon-fast") {
		t.Fatalf("hidden missing amazon-fast: %v", got.Models.Hidden)
	}
}
