package auditwriter

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

// MaxObjectSize bounds one read from the WORM bucket. It equals the exporter's decode limit, and a compressed audit
// object is not larger than its decoded events; a manifest lists one day's objects. A larger object is refused instead
// of being read into the writer's memory (PDK-593).
const MaxObjectSize = 256 << 20

// errObjectTooLarge means an object is larger than the per-object read limit.
var errObjectTooLarge = errors.New("larger than the per-object read limit")

// streamObject copies the object key into w and through a SHA-256 hash; it reads at most limit bytes and fails with
// errObjectTooLarge when the object holds more.
func streamObject(ctx context.Context, store ObjectStore, key string, limit int64, w io.Writer) (sum [32]byte, n int64, err error) {
	body, err := store.Open(ctx, key)
	if err != nil {
		return sum, 0, err
	}
	defer func() { _ = body.Close() }()
	h := sha256.New()
	if n, err = io.Copy(io.MultiWriter(w, h), io.LimitReader(body, limit)); err != nil {
		return sum, n, err
	}
	var one [1]byte
	switch extra, err := io.ReadFull(body, one[:]); {
	case extra > 0:
		return sum, n, fmt.Errorf("%w (%d bytes)", errObjectTooLarge, limit)
	case !errors.Is(err, io.EOF):
		return sum, n, err
	}
	copy(sum[:], h.Sum(nil))
	return sum, n, nil
}
