package auditwriter

import "time"

// Test-only hooks; they exist only in the test binary.

// SetTransactionTimeout lowers the writer's transaction timeout.
func SetTransactionTimeout(w *Writer, d time.Duration) { w.txTimeout = d }

// SetSealerClock replaces the sealer's clock.
func SetSealerClock(s *Sealer, now func() time.Time) { s.now = now }

// EncodeObject renders events as a WORM object body.
var EncodeObject = encodeObject
