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

func TestCovered(t *testing.T) {
	seen := []int64{1, 2, 4}
	dropped := []SeqRange{{5, 6}}
	for _, tt := range []struct {
		r    SeqRange
		want bool
	}{
		{SeqRange{1, 2}, true},
		{SeqRange{3, 3}, false},
		{SeqRange{4, 6}, true},
		{SeqRange{4, 7}, false},
		{SeqRange{2, 4}, false},
	} {
		if got := Covered(tt.r, seen, dropped); got != tt.want {
			t.Errorf("Covered(%v) = %v, want %v", tt.r, got, tt.want)
		}
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
