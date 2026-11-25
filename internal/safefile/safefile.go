// Package safefile provides atomic file write helpers to avoid truncated or
// corrupted state/config/credential files on crash or power loss.
package safefile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

var renameBackoffs = []time.Duration{
	10 * time.Millisecond,
	20 * time.Millisecond,
	40 * time.Millisecond,
	60 * time.Millisecond,
	60 * time.Millisecond,
	60 * time.Millisecond,
}

func isTransientRenameErr(err error) bool {
	if err == nil || runtime.GOOS != "windows" {
		return false
	}
	if errors.Is(err, fs.ErrPermission) {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		// Windows: ERROR_ACCESS_DENIED (5), ERROR_SHARING_VIOLATION (32), ERROR_LOCK_VIOLATION (33).
		switch errno {
		case 5, 32, 33:
			return true
		}
	}
	return false
}

// WriteAtomic writes data to a sibling temporary file, fsyncs it, and renames
// it into place. Parent directories are created automatically.
func WriteAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		// Callers store credentials, keys and runtime state here: keep new directories private.
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmp := f.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmp)
		}
	}()

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if perm != 0 {
		_ = os.Chmod(tmp, perm)
	}

	var renameErr error
	for attempt := 0; ; attempt++ {
		renameErr = os.Rename(tmp, path)
		if renameErr == nil {
			cleanup = false
			return nil
		}
		if attempt >= len(renameBackoffs) || !isTransientRenameErr(renameErr) {
			break
		}
		time.Sleep(renameBackoffs[attempt])
	}
	return fmt.Errorf("rename %s -> %s: %w", tmp, path, renameErr)
}
