package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type mockOIDC struct {
	srv       *httptest.Server
	ov        EndpointOverrides
	codeCalls atomic.Int32
}

func newMockOIDC(t *testing.T, tokenHook func()) *mockOIDC {
	t.Helper()
	m := &mockOIDC{}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/client/register":
			_ = json.NewEncoder(w).Encode(map[string]any{"clientId": "cid_test"})
		case "/token":
			m.codeCalls.Add(1)
			if tokenHook != nil {
				tokenHook()
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"accessToken":  "acc_1",
				"refreshToken": "ref_1",
				"expiresIn":    3600,
			})
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
	t.Cleanup(m.srv.Close)
	m.ov = EndpointOverrides{OIDCBase: m.srv.URL, DiscoveryURL: m.srv.URL + "/sn", DataPlaneURL: m.srv.URL}
	return m
}

// startSocialFlow runs Start + discovery and returns the manager, session id and OAuth state.
func startSocialFlow(t *testing.T, m *mockOIDC, onComplete LoginResultHandler) (*CallbackManager, string, string) {
	t.Helper()
	mgr := NewCallbackManager(nil, onComplete)
	t.Cleanup(mgr.Close)
	view, err := mgr.Start(ProviderSocial, "prod", "us-east-1", 0, "1.2.4660", m.ov)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	lu, _ := url.Parse(view.LoginURL)
	parts := strings.Split(lu.Query().Get("qwSurface"), ":")
	if len(parts) < 2 {
		t.Fatalf("unexpected login url %s", view.LoginURL)
	}
	q := url.Values{}
	q.Set("nonce", parts[1])
	q.Set("issuerUrl", m.srv.URL+"/issuer")
	q.Set("tenantUrl", m.srv.URL)
	q.Set("idcRegion", "us-east-1")
	v2, err := mgr.SubmitCallbackURL(context.Background(), view.SessionID, "http://127.0.0.1/callback?"+q.Encode())
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	au, _ := url.Parse(v2.AuthorizeURL)
	st := au.Query().Get("state")
	if st == "" {
		t.Fatalf("authorize URL has no state: %s", v2.AuthorizeURL)
	}
	return mgr, view.SessionID, st
}

func codeCallbackURL(code, st string) string {
	q := url.Values{}
	q.Set("code", code)
	q.Set("state", st)
	return "http://127.0.0.1/?" + q.Encode()
}

func TestLoginFlowConcurrentCallbacksRedeemCodeOnce(t *testing.T) {
	m := newMockOIDC(t, func() { time.Sleep(50 * time.Millisecond) })
	var saves atomic.Int32
	mgr, sid, st := startSocialFlow(t, m, func(*Account) error {
		saves.Add(1)
		return nil
	})
	cb := codeCallbackURL("code_once", st)

	stop := make(chan struct{})
	pollDone := make(chan struct{})
	go func() { // the panel polls Status every 2s; hammer it to exercise the locking
		defer close(pollDone)
		for {
			select {
			case <-stop:
				return
			default:
				mgr.Status(sid)
				time.Sleep(time.Millisecond)
			}
		}
	}()

	var wg sync.WaitGroup
	var ok atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if v, err := mgr.SubmitCallbackURL(context.Background(), sid, cb); err == nil && v.Status == flowAuthorized {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	close(stop)
	<-pollDone

	if got := m.codeCalls.Load(); got != 1 {
		t.Fatalf("authorization code redeemed %d times, want 1", got)
	}
	if ok.Load() != 1 || saves.Load() != 1 {
		t.Fatalf("successes=%d saves=%d, want 1/1", ok.Load(), saves.Load())
	}
	if v, _ := mgr.Status(sid); v.Status != flowAuthorized || v.AccountUID == "" {
		t.Fatalf("final status %+v", v)
	}
}

func TestLoginFlowStateCheckedBeforeErrorParam(t *testing.T) {
	m := newMockOIDC(t, nil)
	mgr, sid, st := startSocialFlow(t, m, nil)
	ctx := context.Background()

	forged := url.Values{}
	forged.Set("error", "access_denied")
	forged.Set("state", "forged-state")
	if _, err := mgr.SubmitCallbackURL(ctx, sid, "http://127.0.0.1/?"+forged.Encode()); err == nil {
		t.Fatal("forged error callback was accepted")
	}
	if v, _ := mgr.Status(sid); v.Status != flowAwaitingAuthorization {
		t.Fatalf("forged error callback changed status to %q", v.Status)
	}
	rec := httptest.NewRecorder()
	mgr.handleCallbackHTTP(rec, httptest.NewRequest(http.MethodGet, "/?"+forged.Encode(), nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("loopback forged error callback status %d", rec.Code)
	}
	if v, _ := mgr.Status(sid); v.Status != flowAwaitingAuthorization {
		t.Fatalf("loopback forged error callback changed status to %q", v.Status)
	}

	if _, err := mgr.SubmitCallbackURL(ctx, sid, codeCallbackURL("code_ok", st)); err != nil {
		t.Fatalf("valid callback: %v", err)
	}
	if _, err := mgr.SubmitCallbackURL(ctx, sid, codeCallbackURL("code_ok", st)); err == nil {
		t.Fatal("replayed callback accepted")
	}
	if got := m.codeCalls.Load(); got != 1 {
		t.Fatalf("token endpoint called %d times, want 1", got)
	}
}

func TestLoginFlowCancelDuringExchangeDoesNotSave(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	m := newMockOIDC(t, func() {
		entered <- struct{}{}
		<-release
	})
	var saves atomic.Int32
	mgr, sid, st := startSocialFlow(t, m, func(*Account) error {
		saves.Add(1)
		return nil
	})
	errc := make(chan error, 1)
	go func() {
		_, err := mgr.SubmitCallbackURL(context.Background(), sid, codeCallbackURL("code_c", st))
		errc <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("token exchange never started")
	}
	mgr.Cancel(sid)
	close(release)
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("cancelled login reported success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled login never returned")
	}
	if saves.Load() != 0 {
		t.Fatal("cancelled login saved the account")
	}
	if _, ok := mgr.Status(sid); ok {
		t.Fatal("cancelled session still visible")
	}
}

func writeAccountJSON(t *testing.T, path string, a *Account) {
	t.Helper()
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadDirEncryptedWinsOverStalePlaintext(t *testing.T) {
	dir := t.TempDir()
	vault, err := NewVaultFromKey(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	fresh := &Account{
		UID:          "soc_alice_1234",
		Email:        "alice@example.com",
		Provider:     ProviderSocial,
		Stage:        "prod",
		AccessToken:  "rotated_access",
		RefreshToken: "rotated_refresh",
		DeviceID:     NewUUID(),
	}
	if err := SaveAccount(dir, vault, fresh); err != nil {
		t.Fatal(err)
	}
	stale := fresh.Clone()
	stale.AccessToken = "old_access"
	stale.RefreshToken = "old_refresh"
	// Sorts before soc_alice_1234.json, which used to overwrite the rotated token.
	writeAccountJSON(t, filepath.Join(dir, "aaa_legacy.json"), stale)
	bob := &Account{
		UID:          "soc_bob_5678",
		Email:        "bob@example.com",
		Provider:     ProviderSocial,
		Stage:        "prod",
		AccessToken:  "bob_access",
		RefreshToken: "bob_refresh",
	}
	writeAccountJSON(t, filepath.Join(dir, "bbb_import.json"), bob)

	for round := 0; round < 2; round++ {
		loaded, err := LoadDir(dir, vault)
		if err != nil || len(loaded) != 2 {
			t.Fatalf("round %d: loaded %d accounts err=%v", round, len(loaded), err)
		}
		byUID := map[string]*Account{}
		for _, a := range loaded {
			byUID[a.UID] = a
		}
		if a := byUID["soc_alice_1234"]; a == nil || a.RefreshToken != "rotated_refresh" {
			t.Fatalf("round %d: stale plaintext overrode rotated token: %+v", round, a)
		}
		if a := byUID["soc_bob_5678"]; a == nil || a.RefreshToken != "bob_refresh" {
			t.Fatalf("round %d: plaintext account not upgraded: %+v", round, a)
		}
	}
	for _, name := range []string{"aaa_legacy.json", "bbb_import.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("plaintext file %s left on disk (err=%v)", name, err)
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, "soc_bob_5678.json"))
	if err != nil || !IsLocalEncryptedEnvelope(raw) || strings.Contains(string(raw), "bob_refresh") {
		t.Fatalf("upgraded file not encrypted: err=%v", err)
	}
}

func TestScryptParamsBounded(t *testing.T) {
	if !scryptParamsSafe(scryptN, scryptR, scryptP) {
		t.Fatal("default export parameters rejected")
	}
	for _, c := range [][3]int{
		{1 << 20, 32, 1}, // 4 GiB
		{1 << 20, 8, 1},  // 1 GiB
		{30000, 8, 1},    // not a power of two
		{1 << 15, 8, 16}, // CPU cost
		{1 << 14, 0, 1},
	} {
		if scryptParamsSafe(c[0], c[1], c[2]) {
			t.Errorf("params %v accepted", c)
		}
	}

	pass := "correct horse battery staple"
	raw, err := EncryptAccounts([]*Account{{UID: "soc_alice_1234", AccessToken: "a"}}, pass)
	if err != nil {
		t.Fatal(err)
	}
	var b map[string]any
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	kdf := b["kdf"].(map[string]any)
	kdf["n"] = 1 << 20
	kdf["r"] = 32
	crafted, _ := json.Marshal(b)
	start := time.Now()
	if _, err := DecryptAccounts(crafted, pass); err == nil || !strings.Contains(err.Error(), "KDF") {
		t.Fatalf("crafted KDF params not rejected: %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("crafted KDF params were evaluated")
	}
	if accts, err := DecryptAccounts(raw, pass); err != nil || len(accts) != 1 {
		t.Fatalf("round trip failed: %v", err)
	}
}

func TestOpenOrCreateVaultConcurrentSameKey(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "private", "encryption.key")
	const n = 8
	vaults := make([]*Vault, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			vaults[i], errs[i] = OpenOrCreateVault(keyPath, "")
		}(i)
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("vault %d: %v", i, errs[i])
		}
		if !bytes.Equal(vaults[i].key, vaults[0].key) {
			t.Fatalf("vault %d got a different key", i)
		}
	}
	again, err := OpenOrCreateVault(keyPath, "")
	if err != nil || !bytes.Equal(again.key, vaults[0].key) {
		t.Fatalf("reopen: err=%v", err)
	}
	if runtime.GOOS != "windows" {
		if st, err := os.Stat(filepath.Dir(keyPath)); err != nil || st.Mode().Perm() != 0o700 {
			t.Fatalf("key dir perm %v err=%v", st.Mode().Perm(), err)
		}
		if st, err := os.Stat(keyPath); err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("key file perm %v err=%v", st.Mode().Perm(), err)
		}
	}
}

func TestRedirectGuardAndCustomerHostedHosts(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer target.Close()
	offHost := strings.Replace(target.URL, "127.0.0.1", "localhost", 1) + "/x"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/off":
			http.Redirect(w, r, offHost, http.StatusFound)
		case "/same":
			http.Redirect(w, r, "/ok", http.StatusFound)
		case "/ok":
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer srv.Close()

	ctx := context.Background()
	if _, err := doJSONRequest(ctx, nil, http.MethodGet, srv.URL+"/off", nil, nil); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("cross-host redirect to untrusted host not blocked: %v", err)
	}
	if out, err := doJSONRequest(ctx, nil, http.MethodGet, srv.URL+"/same", nil, nil); err != nil || out["ok"] != true {
		t.Fatalf("same-host redirect blocked: %v", err)
	}

	for host, want := range map[string]bool{
		"my-bucket.s3.amazonaws.com":                  true,
		"my-bucket.s3.us-east-1.amazonaws.com":        true,
		"abc123.execute-api.us-east-1.amazonaws.com":  true,
		"ec2-1-2-3-4.compute-1.amazonaws.com":         true,
		"my-lb-1.us-east-1.elb.amazonaws.com":         true,
		"oidc.us-east-1.amazonaws.com":                false,
		"portal.sso.us-east-1.amazonaws.com":          false,
		"cell001.dp.appintegrations.us-east-1.prod.x": false,
	} {
		if got := isCustomerHostedAWSHost(host); got != want {
			t.Errorf("isCustomerHostedAWSHost(%q)=%v want %v", host, got, want)
		}
	}
	if _, err := ValidateTrustedURL("https://evil.s3.us-east-1.amazonaws.com/token", false); err == nil {
		t.Fatal("S3 bucket host accepted as trusted endpoint")
	}
	if _, err := ValidateTrustedURL("https://oidc.us-east-1.amazonaws.com/token", false); err != nil {
		t.Fatalf("OIDC endpoint rejected: %v", err)
	}
	// Untrusted oidc_base override must be rejected during discovery.
	flow := NewLoginFlow(ProviderSocial, "prod", "us-east-1", 18080, "1.2.4660", EndpointOverrides{
		OIDCBase: "https://evil.example.com/oidc",
	})
	q := url.Values{
		"nonce":     {flow.Nonce},
		"issuerUrl": {"https://oidc.us-east-1.amazonaws.com/issuer"},
	}
	if _, err := flow.ProcessDiscovery(ctx, nil, q); err == nil {
		t.Fatal("untrusted oidc_base override was not rejected")
	}
}

func TestCallbackManagerClosesIPv4AndIPv6Servers(t *testing.T) {
	mgr := NewCallbackManager(nil, nil)
	view, err := mgr.Start(ProviderSocial, "prod", "us-east-1", 0, "1.2.4660", EndpointOverrides{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if view.CallbackPort <= 0 || len(mgr.ActivePorts()) != 1 {
		t.Fatalf("expected active callback listener, got port=%d ports=%v", view.CallbackPort, mgr.ActivePorts())
	}
	mgr.Close()
	if len(mgr.ActivePorts()) != 0 {
		t.Fatalf("ActivePorts not cleared after Close: %v", mgr.ActivePorts())
	}
	mgr.mu.Lock()
	rem6 := len(mgr.servers6)
	mgr.mu.Unlock()
	if rem6 != 0 {
		t.Fatalf("servers6 not cleared after Close: %d", rem6)
	}
}

func TestValidateImportedAccountEndpoints(t *testing.T) {
	if err := ValidateImportedAccountEndpoints(nil); err == nil {
		t.Fatal("nil account must be rejected")
	}
	good := &Account{
		Region:        "us-east-1",
		IDCRegion:     "us-east-1",
		TenantURL:     "https://cell001.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev",
		WSHost:        "wss://cell001.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev:443",
		WSPath:        DefaultWSPath,
		TokenEndpoint: "https://oidc.us-east-1.amazonaws.com/token",
	}
	if err := ValidateImportedAccountEndpoints(good); err != nil {
		t.Fatalf("valid account rejected: %v", err)
	}
	bad := good.Clone()
	bad.WSHost = "ws://127.0.0.1:8080"
	if err := ValidateImportedAccountEndpoints(bad); err == nil {
		t.Fatal("plaintext ws:// host must be rejected")
	}
	bad2 := good.Clone()
	bad2.TenantURL = "https://evil.example.com"
	if err := ValidateImportedAccountEndpoints(bad2); err == nil {
		t.Fatal("foreign tenant_url must be rejected")
	}
}

func TestUseOIDCJSONTokenEndpointAlignment(t *testing.T) {
	cases := []struct {
		provider, idcRegion, tokenEP string
		wantJSON                     bool
	}{
		{ProviderSocial, "us-east-1", "https://oidc.us-east-1.amazonaws.com/token", true},
		{ProviderSocial, "", "", true},
		{ProviderSocial, "", "https://oidc.us-west-2.amazonaws.com/token", true},
		{ProviderSocial, "", "https://auth.example.amazoncognito.com/oauth2/token", false},
		{ProviderSocialGateway, "", "https://oidc.us-east-1.amazonaws.com/token", false},
		{ProviderSocialGateway, "us-east-1", "https://quick.aws.com/token", false},
		{ProviderEnterprise, "", "https://quick.aws.com/token", false},
		{ProviderGateway, "", "https://quick.aws.com/token", false},
	}
	for _, tc := range cases {
		if got := useOIDCJSONTokenEndpoint(tc.provider, tc.idcRegion, tc.tokenEP); got != tc.wantJSON {
			t.Errorf("useOIDCJSONTokenEndpoint(%q, %q, %q) = %v, want %v", tc.provider, tc.idcRegion, tc.tokenEP, got, tc.wantJSON)
		}
	}
}

func TestLoadDirDoesNotMarkSeenWhenSaveAccountFails(t *testing.T) {
	dir := t.TempDir()
	vault, err := NewVaultFromKey(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	uid := "soc_fail_save_1"
	acct := &Account{
		UID:          uid,
		Email:        "fail@example.com",
		Provider:     ProviderSocial,
		Stage:        "prod",
		AccessToken:  "tok1",
		RefreshToken: "ref1",
		DeviceID:     NewUUID(),
	}
	// Block SaveAccount from writing <uid>.json by placing a directory at that target path.
	if err := os.Mkdir(filepath.Join(dir, uid+".json"), 0o700); err != nil {
		t.Fatal(err)
	}
	p1 := filepath.Join(dir, "aaa_plain1.json")
	p2 := filepath.Join(dir, "bbb_plain2.json")
	writeAccountJSON(t, p1, acct)
	writeAccountJSON(t, p2, acct)

	loaded, err := LoadDir(dir, vault)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || loaded[0].UID != uid {
		t.Fatalf("expected 1 deduplicated loaded account, got %d", len(loaded))
	}
	// Neither plaintext file may be deleted because SaveAccount failed to persist an encrypted copy.
	for _, p := range []string{p1, p2} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("plaintext credential %s was wrongly deleted after SaveAccount failure: %v", filepath.Base(p), err)
		}
	}
}
