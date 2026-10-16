package problem

import (
	"fmt"
	"net/http"
	"testing"
)

func TestSessionStoreUnavailable(t *testing.T) {
	if SessionStoreUnavailable.Status != http.StatusServiceUnavailable || SessionStoreUnavailable.Code != "session_store_unavailable" {
		t.Fatalf("SessionStoreUnavailable = %+v", SessionStoreUnavailable)
	}
	if got := From(fmt.Errorf("lookup: %w", SessionStoreUnavailable)); got != SessionStoreUnavailable {
		t.Fatalf("From(wrapped) = %+v", got)
	}
}
