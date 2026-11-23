// Package tray implements a zero-CGO pure-Go Windows system tray icon, single-instance
// guard, and HKCU autostart registry helper for console-free background operation.
package tray

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
)

// Config controls the system tray icon, dynamic actions, and startup notification.
type Config struct {
	Tooltip      string
	PanelURL     func() string
	OpenAIBase   func() string
	APIKey       func() string
	AdminKey     func() string
	ConfigDir    string
	LogFile      string
	ExePath      string
	ConfigPath   string
	ShowStartup  bool
	StartupTitle string
	StartupBody  string
	OnQuit       func()
}

// renderTrayIconPNG generates a crisp 32x32 anti-aliased RGBA PNG icon
// (rounded amber-orange badge matching AWS Quick with a bold white "Q").
func renderTrayIconPNG() []byte {
	const size = 32
	img := image.NewNRGBA(image.Rect(0, 0, size, size))

	const (
		cx, cy = 15.5, 15.5
		half   = 13.5
		rad    = 6.0
	)

	roundedRectAlpha := func(x, y float64) float64 {
		dx := math.Abs(x-cx) - (half - rad)
		dy := math.Abs(y-cy) - (half - rad)
		outDist := math.Hypot(math.Max(dx, 0), math.Max(dy, 0))
		inDist := math.Min(math.Max(dx, dy), 0)
		sdf := outDist + inDist - rad
		if sdf <= -0.6 {
			return 1
		}
		if sdf >= 0.6 {
			return 0
		}
		return (0.6 - sdf) / 1.2
	}

	segDist := func(px, py, ax, ay, bx, by float64) float64 {
		vx, vy := bx-ax, by-ay
		wx, wy := px-ax, py-ay
		l2 := vx*vx + vy*vy
		t := 0.0
		if l2 > 0 {
			t = (wx*vx + wy*vy) / l2
			if t < 0 {
				t = 0
			} else if t > 1 {
				t = 1
			}
		}
		return math.Hypot(px-(ax+t*vx), py-(ay+t*vy))
	}

	// Bold stylized "Q": circle ring + diagonal tail.
	letterAlpha := func(x, y float64) float64 {
		ringDist := math.Abs(math.Hypot(x-15.0, y-14.8) - 6.8)
		tailDist := segDist(x, y, 17.8, 18.2, 23.2, 23.6)
		d := math.Min(ringDist, tailDist)
		const strokeHalf = 1.9
		if d <= strokeHalf-0.55 {
			return 1
		}
		if d >= strokeHalf+0.55 {
			return 0
		}
		return (strokeHalf + 0.55 - d) / 1.1
	}

	for y := 0; y < size; y++ {
		t := float64(y) / float64(size-1)
		// Warm amber-orange gradient (#f97316 -> #ea580c)
		br := uint8(math.Round(249*(1-t) + 234*t))
		bg := uint8(math.Round(115*(1-t) + 88*t))
		bb := uint8(math.Round(22*(1-t) + 12*t))

		for x := 0; x < size; x++ {
			ba := roundedRectAlpha(float64(x), float64(y))
			if ba <= 0 {
				continue
			}
			la := letterAlpha(float64(x), float64(y))
			r := uint8(math.Round(float64(br)*(1-la) + 255*la))
			g := uint8(math.Round(float64(bg)*(1-la) + 255*la))
			b := uint8(math.Round(float64(bb)*(1-la) + 255*la))
			a := uint8(math.Round(ba * 255))
			img.SetNRGBA(x, y, color.NRGBA{R: r, G: g, B: b, A: a})
		}
	}

	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}
