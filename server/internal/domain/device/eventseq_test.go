package device

import (
	"reflect"
	"testing"
)

func TestHoles(t *testing.T) {
	capped := make([]int64, SeenLimit)
	for i := range capped {
		capped[i] = int64(i + 1)
	}
	cappedWithHole := make([]int64, SeenLimit)
	for i := range cappedWithHole {
		cappedWithHole[i] = int64(i + 2)
	}
	tests := []struct {
		name       string
		contiguous int64
		high       int64
		seen       []int64
		dropped    []SeqRange
		wantC      int64
		wantHoles  []SeqRange
	}{
		{"nothing delivered, nothing claimed", 0, 0, nil, nil, 0, nil},
		{"no hole", 0, 4, []int64{1, 2, 3, 4}, nil, 4, nil},
		{"no hole above the pointer", 4, 6, []int64{5, 6}, nil, 6, nil},
		{"hole in the middle", 0, 4, []int64{1, 2, 4}, nil, 2, []SeqRange{{3, 3}}},
		{"two holes", 0, 9, []int64{1, 3, 4, 8, 9}, nil, 1, []SeqRange{{2, 2}, {5, 7}}},
		{"trailing hole up to high", 0, 6, []int64{1, 2, 3}, nil, 3, []SeqRange{{4, 6}}},
		{"claimed, nothing delivered", 0, 3, nil, nil, 0, []SeqRange{{1, 3}}},
		{"dropped range bridging a hole", 0, 8, []int64{1, 2, 7, 8}, []SeqRange{{3, 6}}, 8, nil},
		{"dropped range covering part of a hole", 0, 8, []int64{1, 2, 8}, []SeqRange{{3, 5}}, 5, []SeqRange{{6, 7}}},
		{"dropped range above a hole", 0, 8, []int64{1, 8}, []SeqRange{{5, 6}}, 1, []SeqRange{{2, 4}, {7, 7}}},
		{"high below last seen: no trailing hole", 0, 2, []int64{1, 2, 3}, nil, 3, nil},
		{"high below last seen: no hole above high", 0, 2, []int64{1, 2, 5}, nil, 2, nil},
		{"hole below high, delivered above high", 0, 3, []int64{1, 5}, nil, 1, []SeqRange{{2, 3}}},
		{"cap: pointer stops at the last number read", 0, 20000, capped, nil, SeenLimit, nil},
		{"cap: pointer below the cap, holes end at the last number read", 0, 20000, cappedWithHole, nil, 0, []SeqRange{{1, 1}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, holes := Holes(tt.contiguous, tt.high, tt.seen, tt.dropped)
			if c != tt.wantC || !reflect.DeepEqual(holes, tt.wantHoles) {
				t.Fatalf("Holes = %d %v, want %d %v", c, holes, tt.wantC, tt.wantHoles)
			}
		})
	}
}

func TestScan(t *testing.T) {
	tests := []struct {
		name        string
		scanned     int64
		high        int64
		seen        []int64
		dropped     []SeqRange
		wantScanned int64
		wantHoles   []SeqRange
	}{
		{"nothing new", 4, 4, nil, nil, 4, nil},
		{"hole: position moves past it up to high", 0, 4, []int64{1, 2, 4}, nil, 4, []SeqRange{{3, 3}}},
		{"trailing hole up to high", 2, 6, []int64{3}, nil, 6, []SeqRange{{4, 6}}},
		{"delivered above high: position follows the delivered run", 0, 2, []int64{1, 2, 3}, nil, 3, nil},
		{"delivered above high after a gap: position stops at high", 0, 2, []int64{1, 2, 5}, nil, 2, nil},
		{"high below the position: nothing new", 6, 3, nil, nil, 6, nil},
		{"dropped range bridges", 2, 8, []int64{7, 8}, []SeqRange{{3, 6}}, 8, nil},
		{"cap: position stops at the last number read", 3, 50000, window(4, SeenLimit), nil, SeenLimit + 3, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanned, holes := Scan(tt.scanned, tt.high, tt.seen, tt.dropped)
			if scanned != tt.wantScanned || !reflect.DeepEqual(holes, tt.wantHoles) {
				t.Fatalf("Scan = %d %v, want %d %v", scanned, holes, tt.wantScanned, tt.wantHoles)
			}
		})
	}
}

// TestScanPastPermanentHole (PDK-419): a hole at 3 that never fills (the position is past it already) does not keep
// later scans inside the same window.
func TestScanPastPermanentHole(t *testing.T) {
	first, holes := Scan(3, 40000, window(4, SeenLimit), nil)
	if first != SeenLimit+3 || holes != nil {
		t.Fatalf("first scan = %d %v", first, holes)
	}
	above := append(window(first+1, 100), window(first+102, 10)...)
	second, holes := Scan(first, first+111, above, nil)
	if want := []SeqRange{{first + 101, first + 101}}; second != first+111 || !reflect.DeepEqual(holes, want) {
		t.Fatalf("second scan = %d %v, want %d %v", second, holes, first+111, want)
	}
}

func window(from int64, n int) []int64 {
	out := make([]int64, n)
	for i := range out {
		out[i] = from + int64(i)
	}
	return out
}

func TestContiguous(t *testing.T) {
	for _, tt := range []struct {
		name    string
		scanned int64
		open    []SeqRange
		want    int64
	}{
		{"no open range", 9, nil, 9},
		{"below the lowest open range", 9, []SeqRange{{6, 7}, {3, 3}}, 2},
		{"open range starts right after zero", 9, []SeqRange{{1, 4}}, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := Contiguous(tt.scanned, tt.open); got != tt.want {
				t.Fatalf("Contiguous = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestUncovered(t *testing.T) {
	for _, tt := range []struct {
		name string
		r    SeqRange
		cut  []SeqRange
		want []SeqRange
	}{
		{"no cut", SeqRange{3, 6}, nil, []SeqRange{{3, 6}}},
		{"covered", SeqRange{3, 3}, []SeqRange{{3, 5}}, nil},
		{"grown at the end", SeqRange{3, 6}, []SeqRange{{3, 3}}, []SeqRange{{4, 6}}},
		{"cut in the middle", SeqRange{1, 9}, []SeqRange{{7, 7}, {3, 4}}, []SeqRange{{1, 2}, {5, 6}, {8, 9}}},
		{"cut elsewhere", SeqRange{3, 4}, []SeqRange{{8, 9}}, []SeqRange{{3, 4}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := Uncovered(tt.r, tt.cut); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Uncovered = %v, want %v", got, tt.want)
			}
		})
	}
}
