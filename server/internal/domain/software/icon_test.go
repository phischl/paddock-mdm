package software

import (
	"bytes"
	"errors"
	"image"
	"image/png"
	"testing"
)

func pngOf(t *testing.T, w, h int) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewGray(image.Rect(0, 0, w, h))); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestValidateIcon: a PNG of up to 64 KiB and 512 by 512 pixels passes; anything else is ErrIcon.
func TestValidateIcon(t *testing.T) {
	oversized := append(pngOf(t, 8, 8), make([]byte, MaxIconBytes)...)
	cases := map[string]struct {
		icon []byte
		ok   bool
	}{
		"png":           {pngOf(t, 64, 64), true},
		"512 by 512":    {pngOf(t, MaxIconDimension, MaxIconDimension), true},
		"513 wide":      {pngOf(t, MaxIconDimension+1, 1), false},
		"over 64 KiB":   {oversized, false},
		"not a png":     {[]byte("GIF89a"), false},
		"png signature": {[]byte("\x89PNG\r\n\x1a\n"), false},
		"empty":         {nil, false},
	}
	for name, c := range cases {
		err := ValidateIcon(c.icon)
		if c.ok != (err == nil) || err != nil && !errors.Is(err, ErrIcon) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
