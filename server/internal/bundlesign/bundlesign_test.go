package bundlesign

import (
	"context"
	"errors"
	"testing"
)

type fakeReader map[int][]byte

func (f fakeReader) PublicKeys(_ context.Context, key string) (map[int][]byte, error) {
	if key != KeyName {
		return nil, errors.New("wrong key")
	}
	return f, nil
}

func TestPublicKeys(t *testing.T) {
	keys, err := PublicKeys(context.Background(), fakeReader{2: []byte{2}, 1: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0].KeyID != "bundle-signing:v1" || keys[0].PublicKey != "AQ==" || keys[1].KeyID != "bundle-signing:v2" {
		t.Fatalf("keys %+v", keys)
	}
	if _, err := PublicKeys(context.Background(), fakeReader{}); err == nil {
		t.Fatal("empty key accepted")
	}
}
