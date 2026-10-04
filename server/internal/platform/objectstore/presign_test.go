package objectstore

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestPresignGetIsLocalAndForThePublicHost(t *testing.T) {
	p := NewPresigner("https://bundles.example.org:8443", "AKIDEXAMPLE", "secret", "paddock-bundles")
	raw, err := p.PresignGet(context.Background(), "org/o/devices/d/bundles/3.dsse", 120*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "bundles.example.org:8443" || u.Path != "/paddock-bundles/org/o/devices/d/bundles/3.dsse" {
		t.Fatalf("url %s", raw)
	}
	q := u.Query()
	if q.Get("X-Amz-Expires") != "120" || !strings.HasPrefix(q.Get("X-Amz-Credential"), "AKIDEXAMPLE/") || q.Get("X-Amz-Signature") == "" {
		t.Fatalf("query %v", q)
	}
}
