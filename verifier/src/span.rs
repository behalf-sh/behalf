//! Byte-level span extraction.
//!
//! Finds the exact byte span of a top-level member's value inside a raw JSON
//! object line — `payload` for leaves, `head` for the head line — so the bytes
//! fed to PAE are the bytes in the file, verbatim (contract §1.2: the verifier
//! MUST NOT parse-and-reserialize). The scanner is a minimal structural walk:
//! it understands strings, escapes (`\"`, `\\`, `\uXXXX`, and the other
//! single-char escapes) and balanced `{}`/`[]` nesting, and nothing more.
//!
//! It never panics: any malformed structure yields a [`SpanError`].

/// Error from the span scanner. The message is static because the scanner
/// deals in byte offsets, not parsed context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpanError(pub &'static str);

impl std::fmt::Display for SpanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for SpanError {}

/// Extract the byte span `[start, end)` of the value of top-level member
/// `key` in the JSON object encoded by `line`.
///
/// The span covers the value exactly as it appears in the raw bytes — for an
/// object value, from its opening `{` to its matching closing `}` inclusive.
/// Whitespace around structural tokens is tolerated (and excluded from the
/// span); the bytes inside the span are returned untouched.
///
/// A duplicate top-level `key` is rejected: with two spans present the signed
/// bytes would be ambiguous (JSON-smuggling hardening).
pub fn extract_top_level_value(line: &[u8], key: &str) -> Result<(usize, usize), SpanError> {
    let mut s = Scanner { b: line, i: 0 };
    s.skip_ws();
    s.expect(b'{', "line is not a JSON object")?;
    let mut found: Option<(usize, usize)> = None;

    // Empty object?
    s.skip_ws();
    if s.peek() == Some(b'}') {
        return Err(SpanError("key not found in top-level object"));
    }

    loop {
        s.skip_ws();
        let (kstart, kend) = s.scan_string()?;
        s.skip_ws();
        s.expect(b':', "expected ':' after object key")?;
        s.skip_ws();
        let vstart = s.i;
        s.scan_value()?;
        let vend = s.i;
        if s.b.get(kstart..kend) == Some(key.as_bytes()) {
            if found.is_some() {
                return Err(SpanError("duplicate top-level key"));
            }
            found = Some((vstart, vend));
        }
        s.skip_ws();
        match s.next() {
            Some(b',') => {}
            Some(b'}') => break,
            Some(_) => return Err(SpanError("expected ',' or '}' after member")),
            None => return Err(SpanError("unexpected end of object")),
        }
    }

    found.ok_or(SpanError("key not found in top-level object"))
}

/// Convenience wrapper returning the span as a byte slice.
pub fn extract_top_level_bytes<'a>(line: &'a [u8], key: &str) -> Result<&'a [u8], SpanError> {
    let (start, end) = extract_top_level_value(line, key)?;
    // Both offsets come from the scanner walking `line`, so this slice is
    // always in bounds; `get` keeps the no-panic guarantee anyway.
    line.get(start..end)
        .ok_or(SpanError("internal span out of bounds"))
}

struct Scanner<'a> {
    b: &'a [u8],
    i: usize,
}

impl Scanner<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.i += 1;
        Some(c)
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.i += 1;
        }
    }

    fn expect(&mut self, c: u8, msg: &'static str) -> Result<(), SpanError> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(SpanError(msg))
        }
    }

    /// Scan a JSON string starting at the opening quote. Returns the span of
    /// the *content* (between the quotes, escapes untouched); leaves the
    /// cursor just past the closing quote.
    fn scan_string(&mut self) -> Result<(usize, usize), SpanError> {
        self.expect(b'"', "expected string")?;
        let start = self.i;
        loop {
            match self.next() {
                None => return Err(SpanError("unterminated string")),
                Some(b'"') => return Ok((start, self.i - 1)),
                Some(b'\\') => match self.next() {
                    None => return Err(SpanError("unterminated escape")),
                    Some(b'u') => {
                        for _ in 0..4 {
                            match self.next() {
                                Some(c) if c.is_ascii_hexdigit() => {}
                                _ => return Err(SpanError("malformed \\u escape")),
                            }
                        }
                    }
                    // Any other escaped byte is consumed blind; the scanner
                    // only needs to know it cannot terminate the string.
                    Some(_) => {}
                },
                Some(_) => {}
            }
        }
    }

    /// Scan any JSON value starting at the cursor (no leading whitespace).
    /// Leaves the cursor just past the value's final byte.
    fn scan_value(&mut self) -> Result<(), SpanError> {
        match self.peek() {
            None => Err(SpanError("expected value")),
            Some(b'"') => {
                self.scan_string()?;
                Ok(())
            }
            Some(b'{' | b'[') => self.scan_container(),
            // Numbers, true/false/null: consume until a structural delimiter.
            // The pipeline only needs the span; validity is serde's job.
            Some(_) => {
                let start = self.i;
                while let Some(c) = self.peek() {
                    if matches!(c, b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n') {
                        break;
                    }
                    self.i += 1;
                }
                if self.i == start {
                    Err(SpanError("expected value"))
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Scan a balanced `{...}` / `[...]` container, string-aware.
    fn scan_container(&mut self) -> Result<(), SpanError> {
        let mut depth: usize = 0;
        loop {
            match self.peek() {
                None => return Err(SpanError("unbalanced container")),
                Some(b'"') => {
                    self.scan_string()?;
                }
                Some(b'{' | b'[') => {
                    depth += 1;
                    self.i += 1;
                }
                Some(b'}' | b']') => {
                    depth = depth
                        .checked_sub(1)
                        .ok_or(SpanError("unbalanced container"))?;
                    self.i += 1;
                    if depth == 0 {
                        return Ok(());
                    }
                }
                Some(_) => {
                    self.i += 1;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span<'a>(line: &'a [u8], key: &str) -> &'a [u8] {
        extract_top_level_bytes(line, key).expect("span should extract")
    }

    #[test]
    fn simple_object_value() {
        assert_eq!(span(br#"{"payload":{"a":1}}"#, "payload"), br#"{"a":1}"#);
    }

    #[test]
    fn value_in_the_middle() {
        let line = br#"{"kind":"leaf","payload":{"a":{"b":[1,2,"}"]}},"sig":"x"}"#;
        assert_eq!(span(line, "payload"), br#"{"a":{"b":[1,2,"}"]}}"#);
    }

    #[test]
    fn payload_as_last_field() {
        let line = br#"{"a":1,"payload":{"z":[{}]}}"#;
        assert_eq!(span(line, "payload"), br#"{"z":[{}]}"#);
    }

    #[test]
    fn escaped_quotes_inside_strings() {
        let line = br#"{"payload":{"s":"he said \"hi\" {"},"x":1}"#;
        assert_eq!(span(line, "payload"), br#"{"s":"he said \"hi\" {"}"#);
    }

    #[test]
    fn escaped_backslash_before_closing_quote() {
        // The string ends "c:\\" — a backslash escape immediately before the
        // closing quote must not swallow the quote.
        let line = br#"{"payload":{"s":"c:\\"},"x":1}"#;
        assert_eq!(span(line, "payload"), br#"{"s":"c:\\"}"#);
    }

    #[test]
    fn unicode_escapes() {
        // \u007d is '}' and \u0022 is '"' — neither may terminate anything.
        let line = br#"{"payload":{"s":"\u007d\u0022ok"},"n":2}"#;
        assert_eq!(span(line, "payload"), br#"{"s":"\u007d\u0022ok"}"#);
    }

    #[test]
    fn whitespace_variants() {
        let line = br#"{ "a" : 1 , "payload" : { "b" : "}" } , "c" : [ ] }"#;
        assert_eq!(span(line, "payload"), br#"{ "b" : "}" }"#);
    }

    #[test]
    fn nested_key_with_same_name_is_not_top_level() {
        let line = br#"{"wrap":{"payload":{"inner":1}},"payload":{"real":2}}"#;
        assert_eq!(span(line, "payload"), br#"{"real":2}"#);
    }

    #[test]
    fn key_name_as_a_string_value_is_not_a_key() {
        let line = br#"{"a":"payload","payload":{"x":1}}"#;
        assert_eq!(span(line, "payload"), br#"{"x":1}"#);
    }

    #[test]
    fn head_key_extraction() {
        let line = br#"{"kind":"head","head":{"count":47,"chain":"ab"},"sig":{"keyid":"k"}}"#;
        assert_eq!(span(line, "head"), br#"{"count":47,"chain":"ab"}"#);
    }

    #[test]
    fn non_object_value_span_includes_quotes() {
        assert_eq!(span(br#"{"payload":"str","b":2}"#, "payload"), br#""str""#);
        assert_eq!(span(br#"{"payload":123,"b":2}"#, "payload"), b"123");
        assert_eq!(span(br#"{"payload":null}"#, "payload"), b"null");
    }

    #[test]
    fn multibyte_utf8_in_strings() {
        let line = "{\"payload\":{\"s\":\"héllo … 界\"},\"x\":1}".as_bytes();
        assert_eq!(
            span(line, "payload"),
            "{\"s\":\"héllo … 界\"}".as_bytes()
        );
    }

    #[test]
    fn missing_key_is_an_error() {
        assert!(extract_top_level_value(br#"{"a":1}"#, "payload").is_err());
        assert!(extract_top_level_value(br"{}", "payload").is_err());
    }

    #[test]
    fn duplicate_top_level_key_is_rejected() {
        let line = br#"{"payload":{"a":1},"payload":{"b":2}}"#;
        assert_eq!(
            extract_top_level_value(line, "payload"),
            Err(SpanError("duplicate top-level key"))
        );
    }

    #[test]
    fn malformed_inputs_error_not_panic() {
        let cases: &[&[u8]] = &[
            b"",
            b"   ",
            b"[1,2]",
            b"{",
            br#"{"payload""#,
            br#"{"payload":"#,
            br#"{"payload":{"#,
            br#"{"payload":{"a":1}"#,
            br#"{"payload":{"a":"unterminated}"#,
            br#"{"payload":{"a":"\"#,
            br#"{"payload":{"a":"\u12"}}"#,
            br#"{"payload":{"a":"\uzzzz"}}"#,
            br#"{"payload":}"#,
            br#"{42:"not a key"}"#,
            b"\x00\xff\xfe binary garbage",
            br#"{"payload":{"a":1}} trailing"#, // trailing junk after '}' is fine...
        ];
        for case in cases {
            // Must never panic; Ok is acceptable for the trailing-junk case.
            let _ = extract_top_level_value(case, "payload");
        }
    }

    #[test]
    fn every_prefix_of_a_real_line_is_panic_free() {
        let line = br#"{"kind":"leaf","index":3,"payload":{"s":"\"}\\","n":[1,{"x":"\u00e9"}]},"leaf_hash":"ab"}"#;
        for end in 0..=line.len() {
            let _ = extract_top_level_value(&line[..end], "payload");
        }
        // And the full line still extracts.
        assert_eq!(
            span(line, "payload"),
            br#"{"s":"\"}\\","n":[1,{"x":"\u00e9"}]}"#
        );
    }
}
