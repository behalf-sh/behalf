package exportv1_test

import (
	"errors"
	"fmt"
)

// This file is an INDEPENDENT span scanner used only by tests. It
// deliberately does not share code with the writer: the writer builds lines
// by concatenation, and this scanner re-derives the value span from the raw
// line bytes by walking JSON syntax (strings, escapes, nesting), per the
// verifier contract in docs/export-format-v1.md §1.2 ("a scanner that
// respects JSON strings and escapes — it MUST NOT parse-and-reserialize").

// extractTopLevelValue returns the exact byte span of the value for `key` in
// the top-level JSON object encoded by line (no surrounding whitespace
// handling beyond what the format emits: none).
func extractTopLevelValue(line []byte, key string) ([]byte, error) {
	if len(line) == 0 || line[0] != '{' {
		return nil, errors.New("line is not a JSON object")
	}
	i := 1
	for i < len(line) {
		if line[i] == '}' {
			break
		}
		k, next, err := scanString(line, i)
		if err != nil {
			return nil, fmt.Errorf("key at %d: %w", i, err)
		}
		if next >= len(line) || line[next] != ':' {
			return nil, fmt.Errorf("expected ':' at %d", next)
		}
		start := next + 1
		end, err := scanValue(line, start)
		if err != nil {
			return nil, fmt.Errorf("value of %q: %w", k, err)
		}
		if string(k) == key {
			return line[start:end], nil
		}
		i = end
		if i < len(line) && line[i] == ',' {
			i++
			continue
		}
	}
	return nil, fmt.Errorf("key %q not found", key)
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
		return 0, errors.New("unexpected end of line")
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
