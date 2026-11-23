//go:build windows

package tray

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	autostartRegPath   = `Software\Microsoft\Windows\CurrentVersion\Run`
	autostartValueName = "AWSQuick2API"
)

func buildAutostartCommand(exePath, configPath string) string {
	exe := strings.TrimSpace(exePath)
	if abs, err := filepath.Abs(exe); err == nil {
		exe = abs
	}
	cfg := strings.TrimSpace(configPath)
	if cfg != "" {
		if abs, err := filepath.Abs(cfg); err == nil {
			cfg = abs
		}
		return fmt.Sprintf(`"%s" -config "%s"`, exe, cfg)
	}
	return fmt.Sprintf(`"%s"`, exe)
}

func IsAutostartEnabled(exePath, configPath string) bool {
	return isAutostartEnabledInKey(autostartRegPath, autostartValueName, exePath, configPath)
}

func SetAutostartEnabled(exePath, configPath string, enabled bool) error {
	return setAutostartEnabledInKey(autostartRegPath, autostartValueName, exePath, configPath, enabled)
}

func isAutostartEnabledInKey(subKey, valueName, exePath, configPath string) bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, subKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()

	val, _, err := k.GetStringValue(valueName)
	if err != nil || strings.TrimSpace(val) == "" {
		return false
	}
	want := buildAutostartCommand(exePath, configPath)
	if strings.EqualFold(strings.TrimSpace(val), want) {
		return true
	}
	if absExe, err := filepath.Abs(exePath); err == nil && absExe != "" {
		return strings.Contains(strings.ToLower(val), strings.ToLower(absExe))
	}
	return false
}

func setAutostartEnabledInKey(subKey, valueName, exePath, configPath string, enabled bool) error {
	if enabled {
		if strings.TrimSpace(exePath) == "" {
			return fmt.Errorf("executable path is empty")
		}
		k, _, err := registry.CreateKey(registry.CURRENT_USER, subKey, registry.SET_VALUE)
		if err != nil {
			return fmt.Errorf("open registry key: %w", err)
		}
		defer k.Close()
		cmd := buildAutostartCommand(exePath, configPath)
		if err := k.SetStringValue(valueName, cmd); err != nil {
			return fmt.Errorf("write autostart value: %w", err)
		}
		return nil
	}

	k, err := registry.OpenKey(registry.CURRENT_USER, subKey, registry.SET_VALUE)
	if err != nil {
		if err == registry.ErrNotExist {
			return nil
		}
		return fmt.Errorf("open registry key: %w", err)
	}
	defer k.Close()
	if err := k.DeleteValue(valueName); err != nil && err != registry.ErrNotExist {
		return fmt.Errorf("delete autostart value: %w", err)
	}
	return nil
}
