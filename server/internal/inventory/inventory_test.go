package inventory

import "testing"

func TestPolicies(t *testing.T) {
	ps, err := Policies()
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 || ps[0].Key != "disk_encrypted" || ps[1].Key != PolicyAgentRunning {
		t.Fatalf("policies %+v", ps)
	}
	agent := ps[1]
	if agent.Query != "SELECT 1 FROM processes WHERE name = 'paddockd' AND path LIKE '/opt/paddock/agent/%';" ||
		agent.Description == "" {
		t.Fatalf("agent policy %+v", agent)
	}
}

func TestSeverity(t *testing.T) {
	for score, want := range map[float64]string{9.8: "critical", 9: "critical", 7.5: "high", 4: "medium", 3.9: "low", 0: ""} {
		if got := Severity(&score); got != want {
			t.Errorf("Severity(%v) = %q, want %q", score, got, want)
		}
	}
	if Severity(nil) != "" {
		t.Error("unknown score rated")
	}
}
