package auditwriter

import (
	"fmt"
	"math"
)

// toInt32 converts n for a database parameter of type integer. The bound is checked in the same function as the
// conversion, so the narrowing is provably safe to a reader and to static analysis.
func toInt32(n int) (int32, error) {
	if n < math.MinInt32 || n > math.MaxInt32 {
		return 0, fmt.Errorf("%d does not fit into 32 bits", n)
	}
	return int32(n), nil
}
