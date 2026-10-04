// Package canonicaljson produces RFC 8785 (JSON Canonicalization Scheme) output, the byte form that is hashed and
// signed for bundles (architecture §7.2).
package canonicaljson

import (
	"encoding/json"
	"fmt"

	"github.com/gowebpki/jcs"
)

// Transform canonicalizes a JSON document.
func Transform(doc []byte) ([]byte, error) {
	out, err := jcs.Transform(doc)
	if err != nil {
		return nil, fmt.Errorf("canonicaljson: %w", err)
	}
	return out, nil
}

// Marshal encodes v with encoding/json and canonicalizes the result.
func Marshal(v any) ([]byte, error) {
	doc, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonicaljson: %w", err)
	}
	return Transform(doc)
}
