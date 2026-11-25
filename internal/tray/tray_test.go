package tray

import (
	"bytes"
	"image/png"
	"testing"
)

func TestRenderTrayIconPNG(t *testing.T) {
	raw := renderTrayIconPNG()
	if len(raw) == 0 {
		t.Fatal("renderTrayIconPNG returned empty bytes")
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("decode tray icon PNG: %v", err)
	}
	b := img.Bounds()
	if b.Dx() != 32 || b.Dy() != 32 {
		t.Fatalf("expected 32x32 icon, got %dx%d", b.Dx(), b.Dy())
	}
}
