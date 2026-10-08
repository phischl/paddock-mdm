// Package render formats paddockctl's output: YAML documents, plans and tables.
package render

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"
)

// JSONToYAML converts a JSON document to YAML and keeps the key order of the JSON (the order of the paddock.v1
// schema, plan M6c decision 26). github.com/oasdiff/yaml decodes into maps and sorts the keys, so paddockctl emits
// the YAML itself; strings are double-quoted JSON strings, which YAML reads unchanged, or literal blocks when they
// have several lines.
func JSONToYAML(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	root, err := parse(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("render: trailing data after the JSON document")
	}
	var b strings.Builder
	switch root.kind {
	case kindObject:
		if len(root.keys) == 0 {
			b.WriteString("{}\n")
		} else {
			writeObject(&b, root, 0)
		}
	case kindArray:
		if len(root.items) == 0 {
			b.WriteString("[]\n")
		} else {
			writeArray(&b, root, 0)
		}
	default:
		b.WriteString(scalar(root.value, 0) + "\n")
	}
	return []byte(b.String()), nil
}

type kind int

const (
	kindScalar kind = iota
	kindObject
	kindArray
)

type node struct {
	kind  kind
	keys  []string
	items []*node // object values (by key position) or array items
	value any     // scalar: string, json.Number, bool or nil
}

func parse(dec *json.Decoder) (*node, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			n := &node{kind: kindObject}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return nil, err
				}
				v, err := parse(dec)
				if err != nil {
					return nil, err
				}
				n.keys = append(n.keys, k.(string))
				n.items = append(n.items, v)
			}
			_, err := dec.Token()
			return n, err
		case '[':
			n := &node{kind: kindArray}
			for dec.More() {
				v, err := parse(dec)
				if err != nil {
					return nil, err
				}
				n.items = append(n.items, v)
			}
			_, err := dec.Token()
			return n, err
		}
		return nil, fmt.Errorf("render: unexpected %v", t)
	default:
		return &node{kind: kindScalar, value: t}, nil
	}
}

var plainKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func key(k string) string {
	if plainKey.MatchString(k) {
		return k
	}
	return quote(k)
}

func indent(n int) string { return strings.Repeat(" ", n) }

// writeObject writes the keys of n at indentation in; the caller has positioned the first line when first is false.
func writeObject(b *strings.Builder, n *node, in int) {
	for i, k := range n.keys {
		b.WriteString(indent(in) + key(k) + ":")
		writeValue(b, n.items[i], in)
	}
}

func writeArray(b *strings.Builder, n *node, in int) {
	for _, item := range n.items {
		b.WriteString(indent(in) + "-")
		switch {
		case item.kind == kindObject && len(item.keys) > 0:
			// The first key goes on the dash line, the others below it, aligned with the first.
			b.WriteString(" " + key(item.keys[0]) + ":")
			writeValue(b, item.items[0], in+2)
			rest := &node{kind: kindObject, keys: item.keys[1:], items: item.items[1:]}
			writeObject(b, rest, in+2)
		default:
			writeValue(b, item, in)
		}
	}
}

// writeValue writes the value of a key or an array item whose line is open at indentation in.
func writeValue(b *strings.Builder, v *node, in int) {
	switch {
	case v.kind == kindObject && len(v.keys) == 0:
		b.WriteString(" {}\n")
	case v.kind == kindArray && len(v.items) == 0:
		b.WriteString(" []\n")
	case v.kind == kindObject:
		b.WriteString("\n")
		writeObject(b, v, in+2)
	case v.kind == kindArray:
		b.WriteString("\n")
		writeArray(b, v, in+2)
	default:
		b.WriteString(" " + scalar(v.value, in+2) + "\n")
	}
}

func scalar(v any, in int) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case bool:
		if t {
			return "true"
		}
		return "false"
	case json.Number:
		return t.String()
	case string:
		if block, ok := literal(t, in); ok {
			return block
		}
		return quote(t)
	}
	return quote(fmt.Sprint(v))
}

func quote(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSuffix(buf.String(), "\n")
}

// literal renders a multi-line string as a literal block scalar when YAML reads it back unchanged without an
// indentation indicator: printable text without carriage returns whose first line does not start with a space.
func literal(s string, in int) (string, bool) {
	if !strings.Contains(strings.TrimRight(s, "\n"), "\n") || strings.HasPrefix(s, " ") || strings.HasPrefix(s, "\n") {
		return "", false
	}
	for _, r := range s {
		if r == '\r' || (!unicode.IsPrint(r) && r != '\n' && r != '\t') {
			return "", false
		}
	}
	body := strings.TrimRight(s, "\n")
	chomp := "|-"
	switch trailing := len(s) - len(body); {
	case trailing == 1:
		chomp = "|"
	case trailing > 1:
		chomp = "|+"
		body = s[:len(s)-1]
	}
	var b strings.Builder
	b.WriteString(chomp)
	for _, line := range strings.Split(body, "\n") {
		b.WriteString("\n")
		if line != "" {
			b.WriteString(indent(in) + line)
		}
	}
	return b.String(), true
}
