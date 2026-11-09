package software

import (
	"bytes"
	"errors"
	"fmt"
	"image/png"
)

// ErrIcon is the validation error of a catalog icon, answered with 400 invalid_request.
var ErrIcon = errors.New("invalid catalog icon")

var pngSignature = []byte("\x89PNG\r\n\x1a\n")

// ValidateIcon checks a catalog icon (plan M13a decision 11): at most MaxIconBytes, the PNG signature, and a header of
// 1 to MaxIconDimension pixels in each direction. The api checks it on upload, and the compiler again before it writes
// the icon to object storage (architect decision A10-14).
func ValidateIcon(icon []byte) error {
	if len(icon) > MaxIconBytes {
		return fmt.Errorf("%w: icon exceeds %d bytes", ErrIcon, MaxIconBytes)
	}
	if !bytes.HasPrefix(icon, pngSignature) {
		return fmt.Errorf("%w: icon must be a PNG image", ErrIcon)
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(icon))
	if err != nil {
		return fmt.Errorf("%w: icon must be a PNG image", ErrIcon)
	}
	if cfg.Width < 1 || cfg.Height < 1 || cfg.Width > MaxIconDimension || cfg.Height > MaxIconDimension {
		return fmt.Errorf("%w: icon must be at most %d by %d pixels", ErrIcon, MaxIconDimension, MaxIconDimension)
	}
	return nil
}
