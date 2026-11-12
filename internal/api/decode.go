package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/NicoTM77/Mandatary/internal/docker"
)

// fieldKind is the JSON type a request field must have.
type fieldKind int

const (
	kindInt fieldKind = iota + 1
	kindBool
	kindString
)

// fieldKinds is the complete set of operation-specific request fields. Together with
// allowedFields it is the whole request schema: any other property, query parameter
// or body field is refused, so no Docker option can ride along.
var fieldKinds = map[string]fieldKind{
	"tail":            kindInt,
	"stdout":          kindBool,
	"stderr":          kindBool,
	"timestamps":      kindBool,
	"since":           kindString,
	"until":           kindString,
	"follow":          kindBool, // REST only
	"timeout_seconds": kindInt,
}

// AllowedFields lists the operation-specific request fields of op (besides the
// endpoint and container identifiers). allowFollow adds the REST-only follow flag.
func AllowedFields(op docker.Operation, allowFollow bool) []string {
	switch op {
	case docker.OpLogs:
		f := []string{"tail", "stdout", "stderr", "timestamps", "since", "until"}
		if allowFollow {
			f = append(f, "follow")
		}
		return f
	case docker.OpStop, docker.OpRestart:
		return []string{"timeout_seconds"}
	}
	return nil
}

func fieldAllowed(op docker.Operation, allowFollow bool, name string) bool {
	for _, f := range AllowedFields(op, allowFollow) {
		if f == name {
			return true
		}
	}
	return false
}

// DecodeObject strictly decodes raw as exactly one JSON object: no duplicate keys, no
// trailing data, depth-one values kept raw. Anything else is refused.
func DecodeObject(raw []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not an object")
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := kt.(string)
		if !ok {
			return nil, errors.New("bad key")
		}
		if _, dup := out[key]; dup {
			return nil, errors.New("duplicate key")
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		out[key] = v
	}
	if _, err := dec.Token(); err != nil { // closing brace
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data")
	}
	return out, nil
}

// BuildCall turns the identifiers and the operation-specific fields (JSON-raw) into a
// Call. fields must contain only AllowedFields(op, allowFollow) with values of the
// declared JSON type (null is refused); everything else is invalid_request.
func BuildCall(op docker.Operation, endpoint, container string, fields map[string]json.RawMessage, allowFollow bool) (Call, *Problem) {
	if _, ok := SpecFor(op); !ok {
		return Call{}, invalid()
	}
	// A container is a bare Docker name or a full ID. The leading "/" Docker prints in
	// its own API is not part of the contract (it cannot be spelled in a REST path
	// segment, and both adapters must refuse the same inputs).
	if endpoint == "" || len(endpoint) > MaxEndpointBytes || container == "" || len(container) > MaxTargetBytes || container[0] == '/' {
		return Call{}, invalid()
	}
	call := Call{Operation: op, Endpoint: endpoint, Container: container}
	ints := map[string]int{}
	bools := map[string]bool{}
	strs := map[string]string{}
	for name, raw := range fields {
		kind, known := fieldKinds[name]
		if !known || !fieldAllowed(op, allowFollow, name) {
			return Call{}, invalid()
		}
		raw = bytes.TrimSpace(raw)
		if string(raw) == "null" {
			return Call{}, invalid()
		}
		switch kind {
		case kindInt:
			var v int64
			if err := strictUnmarshal(raw, &v); err != nil || v < -1<<31 || v > 1<<31 {
				return Call{}, invalid()
			}
			ints[name] = int(v)
		case kindBool:
			var v bool
			if err := strictUnmarshal(raw, &v); err != nil {
				return Call{}, invalid()
			}
			bools[name] = v
		case kindString:
			var v string
			if err := strictUnmarshal(raw, &v); err != nil {
				return Call{}, invalid()
			}
			strs[name] = v
		}
	}
	switch op {
	case docker.OpLogs:
		o := docker.LogOptions{Stdout: true, Stderr: true}
		if v, ok := ints["tail"]; ok {
			o.Tail = v
			if v == 0 { // 0 would silently mean "default"; an explicit 0 is a malformed request
				return Call{}, invalid()
			}
		}
		if v, ok := bools["stdout"]; ok {
			o.Stdout = v
		}
		if v, ok := bools["stderr"]; ok {
			o.Stderr = v
		}
		o.Timestamps = bools["timestamps"]
		o.Follow = bools["follow"]
		for _, f := range []struct {
			name string
			dst  *time.Time
		}{{"since", &o.Since}, {"until", &o.Until}} {
			if s, ok := strs[f.name]; ok {
				t, err := time.Parse(time.RFC3339Nano, s)
				if err != nil {
					return Call{}, invalid()
				}
				*f.dst = t.UTC()
			}
		}
		call.Logs = &o
		call.Follow = o.Follow
	case docker.OpStop, docker.OpRestart:
		if v, ok := ints["timeout_seconds"]; ok {
			call.TimeoutSeconds = &v
		}
	}
	return call, nil
}

func strictUnmarshal(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

// QueryFields converts a REST query into raw JSON fields: every key must be allowed,
// appear exactly once, and have a value of the field's exact textual form (decimal
// digits, "true"/"false", or a string). Anything else is invalid_request.
func QueryFields(op docker.Operation, query map[string][]string) (map[string]json.RawMessage, *Problem) {
	out := make(map[string]json.RawMessage, len(query))
	if op != docker.OpLogs && len(query) != 0 { // only logs is parameterized by query; stop/restart use a JSON body
		return nil, invalid()
	}
	for name, values := range query {
		kind, known := fieldKinds[name]
		if !known || !fieldAllowed(op, true, name) || len(values) != 1 {
			return nil, invalid()
		}
		v := values[0]
		switch kind {
		case kindInt:
			if !digits(v) {
				return nil, invalid()
			}
			out[name] = json.RawMessage(v)
		case kindBool:
			if v != "true" && v != "false" {
				return nil, invalid()
			}
			out[name] = json.RawMessage(v)
		case kindString:
			b, err := json.Marshal(v)
			if err != nil {
				return nil, invalid()
			}
			out[name] = b
		}
	}
	return out, nil
}

func digits(s string) bool {
	if s == "" || len(s) > 9 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
