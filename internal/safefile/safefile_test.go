package safefile

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteAtomicCreatesPrivateDirAndReplacesContent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "secrets")
	target := filepath.Join(dir, "cred.json")

	first := []byte(`{"version":1}` + "\n")
	if err := WriteAtomic(target, first, 0o600); err != nil {
		t.Fatalf("WriteAtomic first: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, first) {
		t.Fatalf("read first: got=%q err=%v", got, err)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm()&0o077 != 0 {
			t.Fatalf("expected 0700 parent dir, got %v err=%v", fi.Mode().Perm(), err)
		}
		if fi, err := os.Stat(target); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("expected 0600 file, got %v err=%v", fi.Mode().Perm(), err)
		}
	}

	second := []byte(`{"version":2,"longer":"payload"}` + "\n")
	if err := WriteAtomic(target, second, 0o600); err != nil {
		t.Fatalf("WriteAtomic second: %v", err)
	}
	got, err = os.ReadFile(target)
	if err != nil || !bytes.Equal(got, second) {
		t.Fatalf("read second: got=%q err=%v", got, err)
	}
	tmps, _ := filepath.Glob(filepath.Join(dir, ".tmp-*"))
	if len(tmps) != 0 {
		t.Fatalf("leftover temp files: %v", tmps)
	}
}
