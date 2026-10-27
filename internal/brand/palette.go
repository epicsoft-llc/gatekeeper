package brand

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
)

// The colours of version-control.
const (
	DefaultBrand  = "#04a9f3"
	DefaultStrong = "#0270a8"
	DefaultDark   = "#6fd0fb"
)

const ink = "#0b1b2b"

var colorPattern = regexp.MustCompile(`^#[0-9a-f]{6}$`)

// Palette is what the pages and the mail derive from the three colours of the configuration.
type Palette struct {
	Brand, Hover, OnBrand, Strong, Dark, Tint, Line string
	// For rgb(… / alpha) in the CSS.
	BrandRGB, DarkRGB string
}

func ValidColor(color string) bool { return colorPattern.MatchString(color) }

// NewPalette takes colours that passed ValidColor; the text on the brand colour is whichever of ink and white reads better.
func NewPalette(brand, strong, dark string) Palette {
	b, d := rgbOf(brand), rgbOf(dark)
	white := [3]float64{255, 255, 255}
	p := Palette{
		Brand:    brand,
		Hover:    hexOf(mix(b, white, 0.16)),
		OnBrand:  ink,
		Strong:   strong,
		Dark:     dark,
		Tint:     hexOf(mix(b, white, 0.9)),
		Line:     hexOf(mix(b, white, 0.7)),
		BrandRGB: fmt.Sprintf("%.0f %.0f %.0f", b[0], b[1], b[2]),
		DarkRGB:  fmt.Sprintf("%.0f %.0f %.0f", d[0], d[1], d[2]),
	}
	if contrast(b, rgbOf(ink)) < contrast(b, white) {
		p.OnBrand = "#ffffff"
	}
	return p
}

var DefaultPalette = NewPalette(DefaultBrand, DefaultStrong, DefaultDark)

func rgbOf(color string) [3]float64 {
	var c [3]float64
	for i := range c {
		v, _ := strconv.ParseUint(color[1+2*i:3+2*i], 16, 8)
		c[i] = float64(v)
	}
	return c
}

func hexOf(c [3]float64) string {
	return fmt.Sprintf("#%02x%02x%02x", int(math.Round(c[0])), int(math.Round(c[1])), int(math.Round(c[2])))
}

// mix moves a towards b by the share t.
func mix(a, b [3]float64, t float64) [3]float64 {
	var c [3]float64
	for i := range c {
		c[i] = a[i] + (b[i]-a[i])*t
	}
	return c
}

// contrast is the WCAG contrast ratio.
func contrast(a, b [3]float64) float64 {
	la, lb := luminance(a), luminance(b)
	return (math.Max(la, lb) + 0.05) / (math.Min(la, lb) + 0.05)
}

func luminance(c [3]float64) float64 {
	var linear [3]float64
	for i, v := range c {
		v /= 255
		if v <= 0.04045 {
			linear[i] = v / 12.92
		} else {
			linear[i] = math.Pow((v+0.055)/1.055, 2.4)
		}
	}
	return 0.2126*linear[0] + 0.7152*linear[1] + 0.0722*linear[2]
}
