package admin

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
)

// TestToDeviceCommandParams (plan M8e gate A1): the command list shows the params the signed command carries, and
// none when the command has none.
func TestToDeviceCommandParams(t *testing.T) {
	conversion := uuid.NewString()
	out := toDeviceCommand(pgstore.DeviceCommand{ID: uuid.New(), Type: "encrypt_disk", Status: "pending",
		Params: json.RawMessage(`{"conversion_id": "` + conversion + `"}`)})
	if out.Params == nil || (*out.Params)["conversion_id"] != conversion {
		t.Fatalf("params %v", out.Params)
	}
	if out := toDeviceCommand(pgstore.DeviceCommand{ID: uuid.New(), Type: "rotate_admin_password", Params: json.RawMessage(`{}`)}); out.Params == nil || len(*out.Params) != 0 {
		t.Fatalf("empty params %v", out.Params)
	}
}
