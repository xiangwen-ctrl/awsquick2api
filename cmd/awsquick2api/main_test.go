package main

import (
	"bytes"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"awsquick2api/internal/auth"
	"awsquick2api/internal/config"
	"awsquick2api/internal/reqlog"
)

func TestDisplayHostAndMaskKey(t *testing.T) {
	if got := displayHost(":18090"); got != "127.0.0.1:18090" {
		t.Fatalf("displayHost(:18090) = %q", got)
	}
	if got := displayHost("0.0.0.0:18090"); got != "127.0.0.1:18090" {
		t.Fatalf("displayHost(0.0.0.0:18090) = %q", got)
	}
	if got := displayHost("127.0.0.1:8080"); got != "127.0.0.1:8080" {
		t.Fatalf("displayHost(127.0.0.1:8080) = %q", got)
	}
	if got := maskKey(""); got != "<empty>" {
		t.Fatalf("maskKey empty = %q", got)
	}
	if got := maskKey("short"); got != "****" {
		t.Fatalf("maskKey short = %q", got)
	}
	if got := maskKey("qk_0123456789abcdef"); got != "qk_01...cdef" {
		t.Fatalf("maskKey long = %q", got)
	}
}

func TestInsecureKeyWarning(t *testing.T) {
	if w := insecureKeyWarning("127.0.0.1:18090", "", ""); w != "" {
		t.Fatalf("loopback should not warn: %q", w)
	}
	if w := insecureKeyWarning("localhost:18090", "", ""); w != "" {
		t.Fatalf("localhost should not warn: %q", w)
	}
	if w := insecureKeyWarning("0.0.0.0:18090", "", "strong_admin"); w == "" {
		t.Fatal("non-loopback empty api_key should warn")
	}
	if w := insecureKeyWarning("0.0.0.0:18090", "strong_api", "replace_with_your_admin_key"); w == "" {
		t.Fatal("non-loopback default admin_key should warn")
	}
	if w := insecureKeyWarning("0.0.0.0:18090", "strong_api", "strong_admin"); w != "" {
		t.Fatalf("strong keys should not warn: %q", w)
	}
}

func TestBestEffortLogWriterScrubsCredentials(t *testing.T) {
	var buf bytes.Buffer
	w := &bestEffortLogWriter{writers: []io.Writer{&buf}}
	line := "proxy failed: http://alice:superpass@proxy.local:8080 key=qka_0123456789abcdef\n"
	if _, err := w.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "superpass") || strings.Contains(out, "qka_0123456789abcdef") {
		t.Fatalf("credentials leaked through log writer: %q", out)
	}
}

func TestAnchorRelativePaths(t *testing.T) {
	base := t.TempDir()
	cfg := config.Default()
	cfg.AuthDir = "./auths"
	cfg.DataDir = "data"
	anchorRelativePaths(cfg, base)
	if cfg.AuthDir != filepath.Join(base, "auths") {
		t.Fatalf("AuthDir = %q, want %q", cfg.AuthDir, filepath.Join(base, "auths"))
	}
	if cfg.DataDir != filepath.Join(base, "data") {
		t.Fatalf("DataDir = %q, want %q", cfg.DataDir, filepath.Join(base, "data"))
	}
}

func TestImportEncryptedAccountsValidatesEndpoints(t *testing.T) {
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auths")
	vault, err := auth.OpenOrCreateVault(filepath.Join(dir, "encryption.key"), "")
	if err != nil {
		t.Fatal(err)
	}

	good := &auth.Account{
		UID:          "soc_cli_good_1",
		Email:        "good@example.com",
		Provider:     auth.ProviderSocial,
		Stage:        "prod",
		Region:       "us-east-1",
		TenantURL:    "https://cell001.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev",
		WSHost:       "cell001.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev",
		WSPath:       auth.DefaultWSPath,
		AccessToken:  "acc_1",
		RefreshToken: "ref_1",
	}
	poisoned := good.Clone()
	poisoned.UID = "soc_cli_evil_2"
	poisoned.WSHost = "ws://evil.example.com"

	// A bundle containing a tampered endpoint must fail cleanly and persist nothing.
	if _, _, err := importEncryptedAccounts(authDir, vault, []*auth.Account{good.Clone(), poisoned}, false); err == nil {
		t.Fatal("expected endpoint validation error for tampered bundle")
	}
	if loaded, _ := auth.LoadDir(authDir, vault); len(loaded) != 0 {
		t.Fatalf("tampered bundle must not persist any accounts, got %d", len(loaded))
	}

	// Valid bundle imports cleanly and skips existing when overwrite=false.
	imp, skip, err := importEncryptedAccounts(authDir, vault, []*auth.Account{good.Clone()}, false)
	if err != nil || imp != 1 || skip != 0 {
		t.Fatalf("valid import = (%d, %d, %v), want (1, 0, nil)", imp, skip, err)
	}
	imp, skip, err = importEncryptedAccounts(authDir, vault, []*auth.Account{good.Clone()}, false)
	if err != nil || imp != 0 || skip != 1 {
		t.Fatalf("duplicate import = (%d, %d, %v), want (0, 1, nil)", imp, skip, err)
	}
}

func TestFormatStartupErrorDialogScrubsCredentials(t *testing.T) {
	err := errors.New("connect http://alice:superSecret99@proxy.local:8080 failed with key qk_my-secret-key-1234")
	msg := formatStartupErrorDialog(err, "/opt/awsquick2api/data/awsquick2api.log")
	if strings.Contains(msg, "superSecret99") || strings.Contains(msg, "my-secret-key-1234") {
		t.Fatalf("dialog message leaked credentials: %q", msg)
	}
	if !strings.Contains(msg, "/opt/awsquick2api/data/awsquick2api.log") {
		t.Fatalf("dialog message missing log hint: %q", msg)
	}
}

func TestFatalLogPersistsBeforeFileLogClose(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "awsquick2api.log")
	fileLog, err := reqlog.NewRotatingFileWriter(logPath, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	prev := log.Writer()
	log.SetOutput(&bestEffortLogWriter{writers: []io.Writer{fileLog}})
	defer log.SetOutput(prev)

	log.Printf("FATAL: %s", reqlog.ScrubCredentials("listen failed: http://u:pwSecret123@proxy:8080"))
	_ = fileLog.Close()

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "FATAL:") {
		t.Fatalf("FATAL line missing from log file: %q", text)
	}
	if strings.Contains(text, "pwSecret123") {
		t.Fatalf("FATAL line leaked credential: %q", text)
	}
}

func TestLoadConfigOrEnvDefaultsAppliesEnvWhenFileMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.json")
	wantAuth := filepath.Join(t.TempDir(), "custom-auths")
	wantData := filepath.Join(t.TempDir(), "custom-data")
	t.Setenv("AWSQUICK_AUTH_DIR", wantAuth)
	t.Setenv("AWSQUICK_DATA_DIR", wantData)

	cfg, err := loadConfigOrEnvDefaults(missing)
	if err != nil {
		t.Fatalf("loadConfigOrEnvDefaults failed: %v", err)
	}
	if cfg.AuthDir != wantAuth || cfg.DataDir != wantData {
		t.Fatalf("got auth=%q data=%q, want auth=%q data=%q", cfg.AuthDir, cfg.DataDir, wantAuth, wantData)
	}
}
