// Package schema embeds the paddock.v1 JSON Schema (plan M6c decision 13) that paddockctl schema prints.
package schema

import _ "embed"

//go:generate cp ../../../api/schema/paddock.v1.json paddock.v1.json

// JSON is a byte-identical copy of api/schema/paddock.v1.json.
//
//go:embed paddock.v1.json
var JSON []byte
