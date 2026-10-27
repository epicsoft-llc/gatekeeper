package brand

import (
	"bytes"
	"image"
	"image/png"
	"strings"
	"testing"
)

func TestPalette(t *testing.T) {
	p := DefaultPalette
	if p.Brand != "#04a9f3" || p.Strong != "#0270a8" || p.Dark != "#6fd0fb" || p.BrandRGB != "4 169 243" || p.DarkRGB != "111 208 251" {
		t.Errorf("default palette %+v", p)
	}
	if p.Hover != "#2cb7f5" || p.Tint != "#e6f6fe" || p.Line != "#b4e5fb" || p.OnBrand != ink {
		t.Errorf("derived colours %+v", p)
	}
	if dark := NewPalette("#8b0000", "#8b0000", "#ff8080"); dark.OnBrand != "#ffffff" {
		t.Errorf("text on a dark brand colour: %s", dark.OnBrand)
	}
	for color, want := range map[string]bool{"#04a9f3": true, "#000000": true, "#04A9F3": false, "#fff": false, "04a9f3": false, "#04a9f3 ": false, "red": false, "#04a9fg": false} {
		if ValidColor(color) != want {
			t.Errorf("ValidColor(%q) != %v", color, want)
		}
	}
}

func pngOf(t *testing.T, width, height int) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewRGBA(image.Rect(0, 0, width, height))); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestLogo(t *testing.T) {
	if DefaultLogo.Width != 42 || DefaultLogo.Height != 42 || !bytes.Equal(DefaultLogo.PNG, defaultLogo) {
		t.Errorf("default logo %dx%d", DefaultLogo.Width, DefaultLogo.Height)
	}
	if wide, err := ParseLogo(pngOf(t, 200, 50)); err != nil || wide.Width != 168 || wide.Height != 42 {
		t.Errorf("wide logo %dx%d, %v", wide.Width, wide.Height, err)
	}
	valid := pngOf(t, 32, 32)
	cases := map[string]struct {
		data []byte
		want string
	}{
		"gif":       {[]byte("GIF89a\x01\x00\x01\x00"), "not a PNG"},
		"svg":       {[]byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`), "not a PNG"},
		"truncated": {valid[:len(valid)-20], "not a readable PNG"},
		"tiny":      {pngOf(t, 8, 8), "between 16 and 1024"},
		"too wide":  {pngOf(t, 400, 50), "four times"},
		"too large": {append(append([]byte{}, pngSignature...), make([]byte, MaxLogoBytes)...), "at most"},
	}
	for name, c := range cases {
		if _, err := ParseLogo(c.data); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %v, want one containing %q", name, err, c.want)
		}
	}
}
