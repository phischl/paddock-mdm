package acceptance

import (
	"encoding/json"
	"net"
	"testing"
)

func TestRmqPeerHostDecode(t *testing.T) {
	want := net.ParseIP("172.25.5.9")
	for name, in := range map[string]string{
		"string":      `"172.25.5.9"`,
		"ipv4 tuple":  `[172,25,5,9]`,
		"v4-mapped":   `[0,0,0,0,0,65535,44057,1289]`,
		"mapped text": `"::ffff:172.25.5.9"`,
	} {
		var h rmqPeerHost
		if err := json.Unmarshal([]byte(in), &h); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !h.Equal(want) {
			t.Errorf("%s: %v != %v", name, net.IP(h), want)
		}
	}
	var h rmqPeerHost
	if err := json.Unmarshal([]byte(`[0,0,0,0,0,65535,44057,1289]`), &h); err != nil || h.Equal(net.ParseIP("172.25.5.10")) {
		t.Errorf("different address must not match: %v", err)
	}
	for _, bad := range []string{`[1,2,3]`, `[300,1,1,1]`, `{"a":1}`, `"nope"`, `[0,0,0,0,0,0,0,70000]`, `7`} {
		if err := json.Unmarshal([]byte(bad), &h); err == nil {
			t.Errorf("%s: want error", bad)
		}
	}
}
