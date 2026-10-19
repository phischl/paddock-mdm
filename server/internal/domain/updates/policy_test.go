package updates

import "testing"

func TestBundleUpdatePolicy(t *testing.T) {
	s := func(v string) *string { return &v }
	cases := []struct {
		org    string
		groups []*string
		want   string
	}{
		{UpdatePolicyAutomatic, nil, ""},
		{UpdatePolicyManual, nil, UpdatePolicyManual},
		{UpdatePolicyManual, []*string{s(UpdatePolicyAutomatic)}, UpdatePolicyAutomatic},
		{UpdatePolicyManual, []*string{s(UpdatePolicyAutomatic), s(UpdatePolicyManual)}, UpdatePolicyManual},
		{UpdatePolicyAutomatic, []*string{nil, s(UpdatePolicyManual)}, UpdatePolicyManual},
		{UpdatePolicyAutomatic, []*string{s(UpdatePolicyAutomatic)}, ""},
		{UpdatePolicyManual, []*string{nil}, UpdatePolicyManual},
	}
	for i, c := range cases {
		if got := BundleUpdatePolicy(c.org, c.groups); got != c.want {
			t.Errorf("case %d: %q, want %q", i, got, c.want)
		}
	}
}

func TestSettingsRejectUnknownPolicy(t *testing.T) {
	s := Defaults()
	s.AgentUpdatePolicy = "sometimes"
	if s.Validate() == nil {
		t.Fatal("an unknown policy was accepted")
	}
}
