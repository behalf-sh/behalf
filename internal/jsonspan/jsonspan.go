// Package jsonspan extracts the exact byte span of a value inside a
// single-line JSON object, walking JSON syntax (strings, escapes, nesting)
// without ever parse-and-reserializing. It exists because the span rule
// (docs/export-format-v1.md §1.2) makes raw byte spans load-bearing: the
// bytes that were signed are the bytes that must come back out, verbatim.
//
// The Week-1 export tests carry an intentionally independent copy of this
// scanner (internal/exportv1/span_test.go); this package is the production
// version used by the Week-2 log envelope and export bridge.
package jsonspan

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ExtractTopLevelValue returns the exact byte span of the value for key in
// the top-level JSON object encoded by line. The returned slice aliases
// line; callers must not modify it.
func ExtractTopLevelValue(line []byte, key string) ([]byte, error) {
	start, end, err := TopLevelSpan(line, key)
	if err != nil {
		return nil, err
	}
	return line[start:end], nil
}

// TopLevelSpan returns the half-open byte offsets [start, end) of the value
// for key in the top-level JSON object encoded by line. Offsets, rather
// than the aliased slice ExtractTopLevelValue returns, are what a splicer
// needs: the MCP proxy rebuilds a tools/call line around the params._meta
// span and must copy every other byte through untouched.
func TopLevelSpan(line []byte, key string) (int, int, error) {
	if len(line) == 0 || line[0] != '{' {
		return 0, 0, errors.New("jsonspan: line is not a JSON object")
	}
	i := 1
	for i < len(line) {
		if line[i] == '}' {
			break
		}
		k, next, err := scanString(line, i)
		if err != nil {
			return 0, 0, fmt.Errorf("jsonspan: key at %d: %w", i, err)
		}
		if next >= len(line) || line[next] != ':' {
			return 0, 0, fmt.Errorf("jsonspan: expected ':' at %d", next)
		}
		start := next + 1
		end, err := scanValue(line, start)
		if err != nil {
			return 0, 0, fmt.Errorf("jsonspan: value of %q: %w", k, err)
		}
		if string(k) == key {
			return start, end, nil
		}
		i = end
		if i < len(line) && line[i] == ',' {
			i++
			continue
		}
	}
	return 0, 0, fmt.Errorf("jsonspan: key %q not found", key)
}

// TopLevelKeys returns the keys of the top-level JSON object encoded by
// line, in the order they appear, each paired with its value's byte span.
// The proxy uses it to build a payload's field-digest manifest without
// re-serializing any value (Q37).
func TopLevelKeys(line []byte) ([]Field, error) {
	if len(line) == 0 || line[0] != '{' {
		return nil, errors.New("jsonspan: line is not a JSON object")
	}
	var out []Field
	i := 1
	for i < len(line) {
		if line[i] == '}' {
			return out, nil
		}
		keyStart := i
		k, next, err := scanString(line, i)
		if err != nil {
			return nil, fmt.Errorf("jsonspan: key at %d: %w", i, err)
		}
		if next >= len(line) || line[next] != ':' {
			return nil, fmt.Errorf("jsonspan: expected ':' at %d", next)
		}
		start := next + 1
		end, err := scanValue(line, start)
		if err != nil {
			return nil, fmt.Errorf("jsonspan: value of %q: %w", k, err)
		}
		// line[keyStart:next] is the key's complete string literal,
		// quotes included; decode it so escapes yield the real name.
		name, err := unquote(line[keyStart:next])
		if err != nil {
			return nil, fmt.Errorf("jsonspan: key at %d: %w", keyStart, err)
		}
		out = append(out, Field{Name: name, Start: start, End: end})
		i = end
		if i < len(line) && line[i] == ',' {
			i++
			continue
		}
	}
	return nil, errors.New("jsonspan: unterminated object")
}

// Field is one member of a JSON object: its decoded name and the byte span
// of its raw value.
type Field struct {
	Name       string
	Start, End int
}

// unquote decodes a JSON string literal (including its quotes).
func unquote(raw []byte) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", err
	}
	return s, nil
}

// scanString scans a JSON string starting at line[i] == '"'. It returns the
// raw (still-escaped) content and the index just past the closing quote.
func scanString(line []byte, i int) ([]byte, int, error) {
	if i >= len(line) || line[i] != '"' {
		return nil, 0, fmt.Errorf("expected '\"' at %d", i)
	}
	j := i + 1
	for j < len(line) {
		switch line[j] {
		case '\\':
			j += 2
		case '"':
			return line[i+1 : j], j + 1, nil
		default:
			j++
		}
	}
	return nil, 0, errors.New("unterminated string")
}

// scanValue scans one JSON value starting at line[i] and returns the index
// just past its end.
func scanValue(line []byte, i int) (int, error) {
	if i >= len(line) {
		return 0, errors.New("unexpected end of input")
	}
	switch line[i] {
	case '"':
		_, end, err := scanString(line, i)
		return end, err
	case '{', '[':
		depth := 0
		j := i
		for j < len(line) {
			switch line[j] {
			case '"':
				_, next, err := scanString(line, j)
				if err != nil {
					return 0, err
				}
				j = next
			case '{', '[':
				depth++
				j++
			case '}', ']':
				depth--
				j++
				if depth == 0 {
					return j, nil
				}
			default:
				j++
			}
		}
		return 0, errors.New("unbalanced brackets")
	default:
		// number, true, false, null: run to the next structural delimiter.
		j := i
		for j < len(line) {
			switch line[j] {
			case ',', '}', ']':
				return j, nil
			default:
				j++
			}
		}
		return 0, errors.New("unterminated scalar")
	}
}
