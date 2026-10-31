package outbound_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
)

// TestValidateDestination covers the settings rules of plan M9 decision 9.
func TestValidateDestination(t *testing.T) {
	ctx := context.Background()
	p := outbound.Policy{Resolver: stubResolver{"hooks.example.org": []netip.Addr{netip.MustParseAddr("93.184.215.14")}}}
	webhook := func(mut func(*outbound.Destination)) outbound.Destination {
		d := outbound.Destination{Type: outbound.TypeWebhook, Name: "SIEM ingest", FilterMode: outbound.FilterSecurity,
			URL: "https://hooks.example.org/x"}
		if mut != nil {
			mut(&d)
		}
		return d
	}
	email := func(mut func(*outbound.Destination)) outbound.Destination {
		d := outbound.Destination{Type: outbound.TypeEmail, Name: "secops", FilterMode: outbound.FilterAll,
			Recipients: []string{"secops@example.org"}, EmailMinIntervalS: 300}
		if mut != nil {
			mut(&d)
		}
		return d
	}
	many := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("r%d@example.org", i)
		}
		return out
	}
	var unregistered []audit.Code
	for i := 0; i < 201; i++ {
		unregistered = append(unregistered, audit.Code(fmt.Sprintf("x.%d", i)))
	}

	for name, d := range map[string]outbound.Destination{
		"webhook":        webhook(nil),
		"heartbeat 60":   webhook(func(d *outbound.Destination) { d.HeartbeatIntervalS = 60 }),
		"heartbeat 3600": webhook(func(d *outbound.Destination) { d.HeartbeatIntervalS = 3600 }),
		"custom": webhook(func(d *outbound.Destination) {
			d.FilterMode, d.Codes = outbound.FilterCustom, []audit.Code{"admin.login", "device.enrolled"}
		}),
		"email":         email(nil),
		"20 recipients": email(func(d *outbound.Destination) { d.Recipients = many(20) }),
		"interval 60":   email(func(d *outbound.Destination) { d.EmailMinIntervalS = 60 }),
	} {
		if err := p.ValidateDestination(ctx, d); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	for name, tc := range map[string]struct {
		d    outbound.Destination
		want error
	}{
		"empty name":     {webhook(func(d *outbound.Destination) { d.Name = "" }), outbound.ErrInvalidName},
		"long name":      {webhook(func(d *outbound.Destination) { d.Name = strings.Repeat("a", 65) }), outbound.ErrInvalidName},
		"name symbol":    {webhook(func(d *outbound.Destination) { d.Name = "-x" }), outbound.ErrInvalidName},
		"type":           {webhook(func(d *outbound.Destination) { d.Type = "syslog" }), outbound.ErrInvalidType},
		"mode":           {webhook(func(d *outbound.Destination) { d.FilterMode = "some" }), outbound.ErrInvalidFilterMode},
		"custom empty":   {webhook(func(d *outbound.Destination) { d.FilterMode = outbound.FilterCustom }), outbound.ErrInvalidCodes},
		"custom 201":     {webhook(func(d *outbound.Destination) { d.FilterMode, d.Codes = outbound.FilterCustom, unregistered }), outbound.ErrInvalidCodes},
		"custom unknown": {webhook(func(d *outbound.Destination) { d.FilterMode, d.Codes = outbound.FilterCustom, []audit.Code{"x.y"} }), outbound.ErrInvalidCodes},
		"custom internal": {webhook(func(d *outbound.Destination) {
			d.FilterMode, d.Codes = outbound.FilterCustom, []audit.Code{"action.finalized_unknown"}
		}), outbound.ErrInvalidCodes},
		"custom dup": {webhook(func(d *outbound.Destination) {
			d.FilterMode, d.Codes = outbound.FilterCustom, []audit.Code{"admin.login", "admin.login"}
		}), outbound.ErrInvalidCodes},
		"url":            {webhook(func(d *outbound.Destination) { d.URL = "http://hooks.example.org/x" }), outbound.ErrInvalidURL},
		"heartbeat 59":   {webhook(func(d *outbound.Destination) { d.HeartbeatIntervalS = 59 }), outbound.ErrInvalidHeartbeat},
		"heartbeat 3601": {webhook(func(d *outbound.Destination) { d.HeartbeatIntervalS = 3601 }), outbound.ErrInvalidHeartbeat},
		"no recipients":  {email(func(d *outbound.Destination) { d.Recipients = nil }), outbound.ErrInvalidRecipients},
		"21 recipients":  {email(func(d *outbound.Destination) { d.Recipients = many(21) }), outbound.ErrInvalidRecipients},
		"display name":   {email(func(d *outbound.Destination) { d.Recipients = []string{"Sec Ops <secops@example.org>"} }), outbound.ErrInvalidRecipients},
		"angle address":  {email(func(d *outbound.Destination) { d.Recipients = []string{"<secops@example.org>"} }), outbound.ErrInvalidRecipients},
		"not an address": {email(func(d *outbound.Destination) { d.Recipients = []string{"secops"} }), outbound.ErrInvalidRecipients},
		"interval 59":    {email(func(d *outbound.Destination) { d.EmailMinIntervalS = 59 }), outbound.ErrInvalidInterval},
		"interval 3601":  {email(func(d *outbound.Destination) { d.EmailMinIntervalS = 3601 }), outbound.ErrInvalidInterval},
	} {
		if err := p.ValidateDestination(ctx, tc.d); !errors.Is(err, tc.want) {
			t.Errorf("%s: err %v, want %v", name, err, tc.want)
		}
	}
}
