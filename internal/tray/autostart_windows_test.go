//go:build windows

package tray

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows/registry"
)

func TestAutostartExactMatchRejectsSubstring(t *testing.T) {
	subKey := fmt.Sprintf(`Software\AWSQuick2API_Test_%d`, os.Getpid())
	t.Cleanup(func() {
		_ = registry.DeleteKey(registry.CURRENT_USER, subKey)
	})

	dir := t.TempDir()
	exe := filepath.Join(dir, "awsquick2api.exe")
	cfg := filepath.Join(dir, "config.json")
	otherCfg := filepath.Join(dir, "other.json")

	if err := setAutostartEnabledInKey(subKey, autostartValueName, exe, cfg, true); err != nil {
		t.Fatalf("enable autostart: %v", err)
	}
	if !isAutostartEnabledInKey(subKey, autostartValueName, exe, cfg) {
		t.Fatal("expected exact exe+config to report enabled")
	}
	// Substring/prefix collision: same exe with a different config or backup suffix must NOT match.
	if isAutostartEnabledInKey(subKey, autostartValueName, exe, otherCfg) {
		t.Fatal("different config path must not match autostart")
	}
	if isAutostartEnabledInKey(subKey, autostartValueName, exe, "") {
		t.Fatal("empty config must not match entry that specifies -config")
	}
	if isAutostartEnabledInKey(subKey, autostartValueName, exe+".bak", cfg) {
		t.Fatal("different exe suffix must not match autostart")
	}

	if err := setAutostartEnabledInKey(subKey, autostartValueName, exe, cfg, false); err != nil {
		t.Fatalf("disable autostart: %v", err)
	}
	if isAutostartEnabledInKey(subKey, autostartValueName, exe, cfg) {
		t.Fatal("expected disabled after delete")
	}
}
