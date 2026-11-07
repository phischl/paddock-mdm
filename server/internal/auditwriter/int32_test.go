package auditwriter

import (
	"math"
	"testing"
)

func TestToInt32(t *testing.T) {
	maxInt32, minInt32 := int64(math.MaxInt32), int64(math.MinInt32)
	tests := []struct {
		name    string
		in      int64
		want    int32
		wantErr bool
	}{
		{"zero", 0, 0, false},
		{"retention default", 400, 400, false},
		{"largest", maxInt32, math.MaxInt32, false},
		{"smallest", minInt32, math.MinInt32, false},
		{"one above", maxInt32 + 1, 0, true},
		{"one below", minInt32 - 1, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := toInt32(int(tt.in))
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Fatalf("toInt32(%d) = %d, %v; want %d, error %v", tt.in, got, err, tt.want, tt.wantErr)
			}
		})
	}
}
