package agent

import "testing"

func TestBundlesURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://device.paddock.localhost:8443":   "https://bundles.paddock.localhost:8443",
		"https://device.example.org/":             "https://bundles.example.org",
		"https://device.example.org/api":          "https://bundles.example.org",
		"https://paddock.example.org":             "",
		"http://device.example.org":               "",
		"https://evil.example/device.example.org": "",
	} {
		if got := BundlesURL(in); got != want {
			t.Errorf("BundlesURL(%q) = %q, want %q", in, got, want)
		}
	}
}
