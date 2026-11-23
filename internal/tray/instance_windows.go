//go:build windows

package tray

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func singleInstanceMutexName(configAbsPath string) string {
	norm := strings.ToLower(filepath.Clean(strings.TrimSpace(configAbsPath)))
	sum := sha256.Sum256([]byte(norm))
	return `Local\AWSQuick2API_` + hex.EncodeToString(sum[:8])
}

func AcquireSingleInstance(configAbsPath string) (release func(), alreadyRunning bool) {
	name := singleInstanceMutexName(configAbsPath)
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return func() {}, false
	}
	h, err := windows.CreateMutex(nil, false, namePtr)
	if err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			if h != 0 {
				_ = windows.CloseHandle(h)
			}
			return nil, true
		}
		if h != 0 {
			_ = windows.CloseHandle(h)
		}
		return func() {}, false
	}
	return func() {
		_ = windows.CloseHandle(h)
	}, false
}
