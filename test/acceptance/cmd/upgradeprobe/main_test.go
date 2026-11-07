package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestChallengeAnswer(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i * 7)
	}
	text := base64.StdEncoding.EncodeToString(raw)
	got, answer, err := challengeAnswer("  "+text+"\n", []int{1, 2, 10, 20, 43, 44})
	if err != nil || got != text {
		t.Fatalf("challengeAnswer = %q, %v; want the canonical text", got, err)
	}
	if want := string([]byte{text[0], text[1], text[9], text[19], text[42], text[43]}); answer != want {
		t.Errorf("answer = %q, want %q", answer, want)
	}
	for name, c := range map[string]struct {
		file      string
		positions []int
	}{
		"not base64":         {"not a key", []int{1}},
		"16 bytes":           {base64.StdEncoding.EncodeToString(raw[:16]), []int{1}},
		"position 0":         {text, []int{0}},
		"position past text": {text, []int{45}},
		"no positions":       {text, nil},
	} {
		if _, _, err := challengeAnswer(c.file, c.positions); err == nil {
			t.Errorf("%s: no error", name)
		} else if strings.Contains(err.Error(), text) {
			t.Errorf("%s: the error carries the key", name)
		}
	}
}
