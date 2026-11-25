package reqlog

import (
	"os"
	"path/filepath"
	"sync"
)

const defaultLogRotateBytes int64 = 5 << 20

type RotatingFileWriter struct {
	path     string
	maxBytes int64

	mu     sync.Mutex
	f      *os.File
	size   int64
	closed bool
}

func NewRotatingFileWriter(path string, maxBytes int64) (*RotatingFileWriter, error) {
	if maxBytes <= 0 {
		maxBytes = defaultLogRotateBytes
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	var sz int64
	if fi, serr := f.Stat(); serr == nil {
		sz = fi.Size()
	}
	return &RotatingFileWriter{
		path:     path,
		maxBytes: maxBytes,
		f:        f,
		size:     sz,
	}, nil
}

func (w *RotatingFileWriter) Write(p []byte) (int, error) {
	if w == nil || len(p) == 0 {
		return len(p), nil
	}
	data := []byte(scrubCredentials(string(p)))

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return len(p), nil
	}
	if w.f == nil {
		if err := w.openLocked(); err != nil {
			return len(p), nil
		}
	}
	if w.size > 0 && w.size+int64(len(data)) > w.maxBytes {
		w.rotateLocked()
	}
	if w.f != nil {
		if n, err := w.f.Write(data); err == nil {
			w.size += int64(n)
		} else {
			_ = w.f.Close()
			w.f = nil
		}
	}
	return len(p), nil
}

func (w *RotatingFileWriter) openLocked() error {
	_ = os.MkdirAll(filepath.Dir(w.path), 0o700)
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	w.f = f
	w.size = 0
	if fi, serr := f.Stat(); serr == nil {
		w.size = fi.Size()
	}
	return nil
}

func (w *RotatingFileWriter) rotateLocked() {
	if w.f != nil {
		_ = w.f.Close()
		w.f = nil
	}
	backup := w.path + ".1"
	_ = os.Remove(backup)
	_ = os.Rename(w.path, backup)
	_ = w.openLocked()
}

func (w *RotatingFileWriter) Path() string {
	if w == nil {
		return ""
	}
	return w.path
}

func (w *RotatingFileWriter) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if w.f != nil {
		err := w.f.Close()
		w.f = nil
		return err
	}
	return nil
}
