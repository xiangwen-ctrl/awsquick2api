package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateTrustedURL(t *testing.T) {
	good := []string{
		"https://quick.aws.com/sn",
		"https://oidc.us-east-1.amazonaws.com/token",
		"https://cell001.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev",
		"https://accounts.google.com/o/oauth2/v2/auth",
	}
	for _, u := range good {
		if _, err := ValidateTrustedURL(u, false); err != nil {
			t.Errorf("expected trusted URL %q, got err: %v", u, err)
		}
	}
	bad := []string{
		"http://quick.aws.com/sn",
		"https://evil.example.com/token",
		"https://169.254.169.254/latest/meta-data",
		"https://quick.aws.com:8443/sn",
		"https://user:pass@quick.aws.com/sn",
	}
	for _, u := range bad {
		if _, err := ValidateTrustedURL(u, false); err == nil {
			t.Errorf("expected rejection for %q", u)
		}
	}
	if _, err := ValidateTrustedURL("http://127.0.0.1:39100/token", true); err != nil {
		t.Errorf("expected localhost override allowed when allowCustom=true, got: %v", err)
	}
}

func TestVaultEncryptedStorageAndLegacyUpgrade(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "encryption.key")
	authDir := filepath.Join(dir, "auths")
	if err := os.MkdirAll(authDir, 0o700); err != nil {
		t.Fatal(err)
	}

	vault, err := OpenOrCreateVault(keyPath, "")
	if err != nil {
		t.Fatalf("OpenOrCreateVault: %v", err)
	}

	acct := &Account{
		UID:          "soc_alice_1234",
		Email:        "alice@example.com",
		Provider:     ProviderSocial,
		Stage:        "prod",
		Region:       "us-east-1",
		TenantURL:    "https://cell001.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev",
		AccessToken:  "super_secret_access_token",
		RefreshToken: "super_secret_refresh_token",
		ExpiresAt:    time.Now().Add(time.Hour).UnixMilli(),
		DeviceID:     NewUUID(),
	}
	if err := SaveAccount(authDir, vault, acct); err != nil {
		t.Fatalf("SaveAccount: %v", err)
	}

	// Verify file on disk has zero plaintext tokens.
	onDisk, err := os.ReadFile(filepath.Join(authDir, acct.UID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !IsLocalEncryptedEnvelope(onDisk) {
		t.Fatalf("expected encrypted envelope on disk, got: %s", string(onDisk))
	}
	if strings.Contains(string(onDisk), "super_secret_access_token") || strings.Contains(string(onDisk), "super_secret_refresh_token") {
		t.Fatal("plaintext token leaked to disk!")
	}

	// Wrong key must fail to decrypt.
	otherVault, _ := OpenOrCreateVault(filepath.Join(dir, "other.key"), "")
	if _, err := otherVault.OpenAccount(acct.UID, onDisk); err == nil {
		t.Fatal("expected decryption failure with wrong key")
	}

	// Re-open with same key succeeds.
	vault2, err := OpenOrCreateVault(keyPath, "")
	if err != nil {
		t.Fatalf("re-open vault: %v", err)
	}
	loaded, err := LoadDir(authDir, vault2)
	if err != nil || len(loaded) != 1 || loaded[0].RefreshToken != "super_secret_refresh_token" {
		t.Fatalf("LoadDir mismatch: loaded=%+v err=%v", loaded, err)
	}

	// Legacy plaintext account file should be auto-upgraded to encrypted format on LoadDir.
	legacy := &Account{
		UID:          "soc_legacy_9999",
		Email:        "legacy@example.com",
		Provider:     ProviderSocial,
		Stage:        "prod",
		AccessToken:  "legacy_plain_token",
		RefreshToken: "legacy_plain_refresh",
		DeviceID:     NewUUID(),
	}
	legacyBytes, _ := json.Marshal(legacy)
	legacyPath := filepath.Join(authDir, legacy.UID+".json")
	if err := os.WriteFile(legacyPath, legacyBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded2, err := LoadDir(authDir, vault2)
	if err != nil || len(loaded2) != 2 {
		t.Fatalf("expected 2 accounts after legacy upgrade, got %d err=%v", len(loaded2), err)
	}
	upgradedDisk, _ := os.ReadFile(legacyPath)
	if !IsLocalEncryptedEnvelope(upgradedDisk) || strings.Contains(string(upgradedDisk), "legacy_plain_token") {
		t.Fatal("legacy plaintext file was not auto-encrypted on load!")
	}
}

func TestSocialLoginAndRefreshMockOIDC(t *testing.T) {
	var refreshCalls int
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/client/register":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"clientId":     "cid_test",
				"clientSecret": "csec_test",
			})
		case "/token":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			switch body["grantType"] {
			case "authorization_code":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"accessToken":  "acc_1",
					"refreshToken": "ref_1",
					"expiresIn":    3600,
				})
			case "refresh_token":
				refreshCalls++
				if body["refreshToken"] == "ref_expired" {
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
					return
				}
				if body["refreshToken"] == "ref_transient" {
					w.WriteHeader(http.StatusServiceUnavailable)
					_ = json.NewEncoder(w).Encode(map[string]any{"error": "temporarily_unavailable"})
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"accessToken":  "acc_2",
					"refreshToken": "ref_2",
					"expiresIn":    3600,
				})
			}
		case "/integration/quick-work/user-info":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"userInfo": map[string]any{
					"email":        "alice@example.com",
					"displayName":  "Alice",
					"userArn":      "arn:aws:quicksight:us-east-1:123456789012:user/default/alice",
					"awsAccountId": "123456789012",
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	ov := EndpointOverrides{
		OIDCBase:     srv.URL,
		DiscoveryURL: srv.URL + "/sn",
		DataPlaneURL: srv.URL,
	}

	var savedAcct *Account
	cbMgr := NewCallbackManager(nil, func(acct *Account) error {
		savedAcct = acct
		return nil
	})
	defer cbMgr.Close()

	view, err := cbMgr.Start(ProviderSocial, "prod", "us-east-1", 0, "1.2.4660", ov)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	u, _ := url.Parse(view.LoginURL)
	nonce := strings.Split(u.Query().Get("qwSurface"), ":")[1]

	step1URL := "http://localhost:18080/callback?nonce=" + url.QueryEscape(nonce) +
		"&issuerUrl=" + url.QueryEscape(srv.URL+"/issuer") +
		"&tenantUrl=" + url.QueryEscape(srv.URL) +
		"&idcRegion=us-east-1"
	v2, err := cbMgr.SubmitCallbackURL(context.Background(), view.SessionID, step1URL)
	if err != nil {
		t.Fatalf("SubmitCallbackURL step1: %v", err)
	}
	au, _ := url.Parse(v2.AuthorizeURL)
	state := au.Query().Get("state")

	step2URL := "http://127.0.0.1:18080/?code=code_123&state=" + url.QueryEscape(state)
	v3, err := cbMgr.SubmitCallbackURL(context.Background(), view.SessionID, step2URL)
	if err != nil || v3.Status != "authorized" || savedAcct == nil {
		t.Fatalf("SubmitCallbackURL step2 failed: view=%+v err=%v", v3, err)
	}

	refreshed, err := RefreshTokens(context.Background(), srv.Client(), savedAcct, ov)
	if err != nil || refreshed.AccessToken != "acc_2" || refreshed.RefreshToken != "ref_2" || refreshed.DeviceID != savedAcct.DeviceID {
		t.Fatalf("RefreshTokens mismatch: %+v err=%v", refreshed, err)
	}
	if refreshCalls != 1 {
		t.Fatalf("expected 1 refresh call, got %d", refreshCalls)
	}

	expAcct := savedAcct.Clone()
	expAcct.RefreshToken = "ref_expired"
	_, err = RefreshTokens(context.Background(), srv.Client(), expAcct, ov)
	if se, ok := err.(*StepError); !ok || !se.Expired {
		t.Fatalf("expected expired StepError, got %v", err)
	}

	trAcct := savedAcct.Clone()
	trAcct.RefreshToken = "ref_transient"
	_, err = RefreshTokens(context.Background(), srv.Client(), trAcct, ov)
	if se, ok := err.(*StepError); !ok || se.Expired {
		t.Fatalf("expected non-expired transient StepError, got %v", err)
	}
}

func TestEncryptedTransferRoundTrip(t *testing.T) {
	accts := []*Account{
		{
			UID:          "soc_alice_1234",
			Email:        "alice@example.com",
			Provider:     ProviderSocial,
			Stage:        "prod",
			Region:       "us-east-1",
			TenantURL:    "https://cell001.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev",
			AccessToken:  "secret_access",
			RefreshToken: "secret_refresh",
			ExpiresAt:    time.Now().Add(time.Hour).UnixMilli(),
			DeviceID:     NewUUID(),
		},
	}

	if _, err := EncryptAccounts(accts, "short"); err == nil {
		t.Fatal("expected error for passphrase < 12 chars")
	}
	sealed, err := EncryptAccounts(accts, "super-secret-passphrase-2026")
	if err != nil {
		t.Fatalf("EncryptAccounts: %v", err)
	}
	if !IsEncryptedBundle(sealed) || strings.Contains(string(sealed), "secret_access") {
		t.Fatal("invalid encrypted bundle")
	}
	if _, err := DecryptAccounts(sealed, "wrong-passphrase-2026"); err == nil {
		t.Fatal("expected decryption failure with wrong passphrase")
	}
	got, err := DecryptAccounts(sealed, "super-secret-passphrase-2026")
	if err != nil || len(got) != 1 || got[0].RefreshToken != "secret_refresh" {
		t.Fatalf("decrypted mismatch: %+v err=%v", got, err)
	}
}
