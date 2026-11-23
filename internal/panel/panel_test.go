package panel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
