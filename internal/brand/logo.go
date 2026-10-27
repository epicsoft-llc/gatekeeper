package brand

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"image/png"
)

// The logo travels with every code mail.
const MaxLogoBytes = 64 << 10

// The mail shows the logo at this height.
const logoHeight = 42

var pngSignature = []byte("\x89PNG\r\n\x1a\n")

//go:embed logo.png
var defaultLogo []byte

// DefaultLogo is Default as a PNG.
var DefaultLogo = mustParseLogo(defaultLogo)

// Logo is the image of the code mail with its size in the mail.
type Logo struct {
	PNG           []byte
	Width, Height int
}

func mustParseLogo(data []byte) Logo {
	logo, err := ParseLogo(data)
	if err != nil {
		panic("brand: logo.png: " + err.Error())
	}
	return logo
}

func ParseLogo(data []byte) (Logo, error) {
	if len(data) > MaxLogoBytes {
		return Logo{}, fmt.Errorf("%d bytes, at most %d are allowed", len(data), MaxLogoBytes)
	}
	if !bytes.HasPrefix(data, pngSignature) {
		return Logo{}, errors.New("not a PNG file")
	}
	size, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return Logo{}, fmt.Errorf("not a readable PNG: %w", err)
	}
	if size.Width < 16 || size.Height < 16 || size.Width > 1024 || size.Height > 1024 || size.Width > 4*size.Height || size.Height > 4*size.Width {
		return Logo{}, fmt.Errorf("%dx%d pixels - width and height lie between 16 and 1024, one at most four times the other", size.Width, size.Height)
	}
	if _, err := png.Decode(bytes.NewReader(data)); err != nil {
		return Logo{}, fmt.Errorf("not a readable PNG: %w", err)
	}
	return Logo{PNG: data, Width: (logoHeight*size.Width + size.Height/2) / size.Height, Height: logoHeight}, nil
}
