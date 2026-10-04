package config

import (
	"strings"
	"testing"
	"time"
)

func TestParseAgent(t *testing.T) {
	const org = "0190f000-0000-7000-8000-00000000000a"
	tests := []struct {
		name    string
		in      string
		want    Agent
		wantErr string
	}{
		{name: "minimal", in: "server_url: https://device.example\norganization_id: " + org + "\n",
			want: Agent{ServerURL: "https://device.example", OrganizationID: org, DriftInterval: DefaultDriftInterval}},
		{name: "quotes, comments and proxy", in: "# c\n\nserver_url: \"https://d.example:8443\"\norganization_id: '" + org + "'\nproxy: http://proxy:3128\ndrift_interval_s: 600\n",
			want: Agent{ServerURL: "https://d.example:8443", OrganizationID: org, Proxy: "http://proxy:3128", DriftInterval: 600 * time.Second}},
		{name: "unknown key", in: "server_url: https://d\norganization_id: " + org + "\nserverurl: x\n", wantErr: "unknown key"},
		{name: "plain http", in: "server_url: http://d\norganization_id: " + org + "\n", wantErr: "https"},
		{name: "bad organization", in: "server_url: https://d\norganization_id: acme\n", wantErr: "organization_id"},
		{name: "no colon", in: "server_url\n", wantErr: "key: value"},
		{name: "bad proxy", in: "server_url: https://d\norganization_id: " + org + "\nproxy: socks5://p\n", wantErr: "proxy"},
		{name: "drift not a number", in: "server_url: https://d\norganization_id: " + org + "\ndrift_interval_s: often\n", wantErr: "integer"},
		{name: "drift below minimum", in: "server_url: https://d\norganization_id: " + org + "\ndrift_interval_s: 10\n", wantErr: "at least"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAgent([]byte(tt.in))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("got %+v, %v; want %+v", got, err, tt.want)
			}
		})
	}
}

func TestAgentRoundTrip(t *testing.T) {
	in := Agent{ServerURL: "https://d.example", OrganizationID: "0190f000-0000-7000-8000-00000000000a", Proxy: "https://p:1", DriftInterval: 900 * time.Second}
	got, err := ParseAgent(in.Marshal())
	if err != nil || got != in {
		t.Fatalf("round trip: %+v, %v", got, err)
	}
}

func TestParseEnrollment(t *testing.T) {
	valid := `{"server_url":"https://d","organization_id":"0190f000-0000-7000-8000-00000000000a","token":"t",` +
		`"bundle_keys":[{"key_id":"bundle-signing:v1","public_key":"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="}]}`
	if _, err := ParseEnrollment([]byte(valid)); err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}
	for name, in := range map[string]string{
		"not json":      "token",
		"unknown field": strings.Replace(valid, `"token"`, `"tokn":"x","token"`, 1),
		"empty token":   strings.Replace(valid, `"token":"t"`, `"token":""`, 1),
		"no keys":       strings.Replace(valid, `[{"key_id":"bundle-signing:v1","public_key":"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="}]`, `[]`, 1),
		"bad key":       strings.Replace(valid, `O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=`, `AAAA`, 1),
		"http url":      strings.Replace(valid, `https://d`, `http://d`, 1),
	} {
		if _, err := ParseEnrollment([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
