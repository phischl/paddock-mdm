package revocation

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestLimitExceeded(t *testing.T) {
	cases := map[string]struct {
		counts Counts
		want   string
	}{
		"none":                {Counts{}, ""},
		"third in an hour":    {Counts{AdminLastHour: 2, AdminLastDay: 2, OrgLastDay: 2}, ""},
		"fourth in an hour":   {Counts{AdminLastHour: 3, AdminLastDay: 3, OrgLastDay: 3}, RejectedAdminHour},
		"tenth in a day":      {Counts{AdminLastHour: 0, AdminLastDay: 9, OrgLastDay: 9}, ""},
		"eleventh in a day":   {Counts{AdminLastHour: 0, AdminLastDay: 10, OrgLastDay: 10}, RejectedAdminDay},
		"twentieth in org":    {Counts{OrgLastDay: 19}, ""},
		"twenty-first in org": {Counts{OrgLastDay: 20}, RejectedOrgDay},
	}
	for name, c := range cases {
		if got := LimitExceeded(c.counts); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}

func TestApprovals(t *testing.T) {
	if Approvals(ActionDestroy) != 2 || Approvals(ActionLock) != 1 || Approvals(ActionSelfLock) != 0 {
		t.Fatal("approvals per action")
	}
}

func TestValidReason(t *testing.T) {
	if !ValidReason("") || !ValidReason(strings.Repeat("ä", MaxReasonLength)) {
		t.Fatal("valid reason refused")
	}
	if ValidReason(strings.Repeat("a", MaxReasonLength+1)) || ValidReason("\xff") {
		t.Fatal("invalid reason accepted")
	}
}

func TestFinal(t *testing.T) {
	for _, s := range Statuses {
		want := s == StatusConfirmed || s == StatusFailed || s == StatusRejected || s == StatusCancelled || s == StatusExpired
		if Final(s) != want {
			t.Errorf("%s: final %v", s, !want)
		}
	}
}

func TestSubject(t *testing.T) {
	org := uuid.Must(uuid.NewV7())
	if got, ok := ParseSubject(Subject(org)); !ok || got != org {
		t.Fatalf("round trip: %v %v", got, ok)
	}
	for _, s := range []string{"command." + org.String(), "revocation.x", "revocation"} {
		if _, ok := ParseSubject(s); ok {
			t.Errorf("%q accepted", s)
		}
	}
}
