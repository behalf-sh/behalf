package jsonspan

import (
	"bytes"
	"testing"
)

func TestExtractTopLevelValue(t *testing.T) {
	line := []byte(`{"a":{"nested":"br}ace","esc":"q\"uote"},"b":[1,{"c":2}],"d":"s","e":42,"f":null}`)
	cases := []struct {
		key  string
		want string
	}{
		{"a", `{"nested":"br}ace","esc":"q\"uote"}`},
		{"b", `[1,{"c":2}]`},
		{"d", `"s"`},
		{"e", `42`},
		{"f", `null`},
	}
	for _, c := range cases {
		got, err := ExtractTopLevelValue(line, c.key)
		if err != nil {
			t.Fatalf("key %q: %v", c.key, err)
		}
		if !bytes.Equal(got, []byte(c.want)) {
			t.Fatalf("key %q: got %s, want %s", c.key, got, c.want)
		}
	}
	if _, err := ExtractTopLevelValue(line, "missing"); err == nil {
		t.Fatal("expected error for missing key")
	}
	if _, err := ExtractTopLevelValue([]byte(`[1,2]`), "a"); err == nil {
		t.Fatal("expected error for non-object")
	}
}

// TestTopLevelSpanOffsets: the offsets a splicer needs must bracket exactly
// the value ExtractTopLevelValue returns, so rebuilding a line around them
// copies every other byte through untouched.
func TestTopLevelSpanOffsets(t *testing.T) {
	line := []byte(`{"a":{"nested":"br}ace"},"b":[1,{"c":2}],"d":"s"}`)
	for _, key := range []string{"a", "b", "d"} {
		start, end, err := TopLevelSpan(line, key)
		if err != nil {
			t.Fatalf("key %q: %v", key, err)
		}
		want, err := ExtractTopLevelValue(line, key)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(line[start:end], want) {
			t.Fatalf("key %q: span %q, value %q", key, line[start:end], want)
		}
		// Splicing the value back in reproduces the line byte for byte.
		var rebuilt []byte
		rebuilt = append(rebuilt, line[:start]...)
		rebuilt = append(rebuilt, want...)
		rebuilt = append(rebuilt, line[end:]...)
		if !bytes.Equal(rebuilt, line) {
			t.Fatalf("key %q: rebuilding around the span changed the line:\n  %s\n  %s", key, line, rebuilt)
		}
	}
}

// TestTopLevelKeys walks an object's members in order, decoding escaped
// names and bracketing each raw value.
func TestTopLevelKeys(t *testing.T) {
	line := []byte(`{"a":1,"sh.behalf/chain":{"chain":[]},"esc\"aped":"v","z":null}`)
	fields, err := TopLevelKeys(line)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		name  string
		value string
	}{
		{"a", "1"},
		{"sh.behalf/chain", `{"chain":[]}`},
		{`esc"aped`, `"v"`},
		{"z", "null"},
	}
	if len(fields) != len(want) {
		t.Fatalf("got %d fields, want %d", len(fields), len(want))
	}
	for i, w := range want {
		if fields[i].Name != w.name {
			t.Fatalf("field %d name %q, want %q", i, fields[i].Name, w.name)
		}
		if got := string(line[fields[i].Start:fields[i].End]); got != w.value {
			t.Fatalf("field %d value %q, want %q", i, got, w.value)
		}
	}
	if _, err := TopLevelKeys([]byte(`{}`)); err != nil {
		t.Fatalf("empty object: %v", err)
	}
	if _, err := TopLevelKeys([]byte(`[1]`)); err == nil {
		t.Fatal("expected error for non-object")
	}
	if _, err := TopLevelKeys([]byte(`{"a":1`)); err == nil {
		t.Fatal("expected error for an unterminated object")
	}
}
