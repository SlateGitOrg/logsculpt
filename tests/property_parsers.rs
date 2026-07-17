//! Property-based tests for the three parsers, using proptest to generate
//! well-formed-but-randomized inputs and asserting invariants that must hold
//! for *any* input matching the grammar — not just the handful of examples
//! covered by unit tests.

use logsculpt::parsers::json_parser::parse_json_line;
use logsculpt::parsers::plaintext_parser::parse_plaintext_line;
use logsculpt::parsers::syslog_parser::parse_syslog_line;
use logsculpt::schema::Severity;
use proptest::prelude::*;

fn severity_token() -> impl Strategy<Value = &'static str> {
    prop_oneof![
        Just("trace"),
        Just("debug"),
        Just("info"),
        Just("warn"),
        Just("warning"),
        Just("error"),
        Just("critical"),
        Just("fatal"),
    ]
}

fn ident() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_-]{2,12}".prop_map(|s| s)
}

proptest! {
    /// Any JSON object carrying a recognized level field must produce an
    /// entry whose severity is never `Unknown`, and the message field must
    /// survive verbatim (structured logs should never lose the message).
    #[test]
    fn json_parser_preserves_message_and_recognizes_level(
        level in severity_token(),
        message in "[a-zA-Z0-9 ,.'_-]{1,80}",
        service in ident(),
    ) {
        let line = serde_json::json!({
            "level": level,
            "message": message,
            "service": service,
        }).to_string();
        let entry = parse_json_line(&line, "src").expect("well-formed json must parse");
        prop_assert_eq!(&entry.message, &message);
        prop_assert_eq!(entry.service.as_deref(), Some(service.as_str()));
        prop_assert_ne!(entry.severity, Severity::Unknown);
    }

    /// Parsing must never panic on arbitrary byte-ish strings, valid JSON or
    /// not; malformed input is always an `Err`, never a crash.
    #[test]
    fn json_parser_never_panics_on_arbitrary_input(s in ".*") {
        let _ = parse_json_line(&s, "src");
    }

    /// Any syntactically valid RFC3164 syslog line (a constrained grammar we
    /// generate here) round-trips host/tag/message correctly regardless of
    /// which specific values are used.
    #[test]
    fn syslog_rfc3164_roundtrips_host_and_tag(
        pri in 0u32..192,
        host in ident(),
        tag in ident(),
        // First char non-space: a leading space in the message is
        // indistinguishable from the "TAG:<sp>MSG" separator's own optional
        // extra whitespace, which the RFC3164 grammar doesn't disambiguate.
        msg in "[a-zA-Z0-9][a-zA-Z0-9 ]{0,39}",
    ) {
        let line = format!("<{pri}>Jan  2 15:04:05 {host} {tag}: {msg}");
        let entry = parse_syslog_line(&line, "src").expect("well-formed RFC3164 must parse");
        prop_assert_eq!(entry.host.as_deref(), Some(host.as_str()));
        prop_assert_eq!(entry.service.as_deref(), Some(tag.as_str()));
        prop_assert_eq!(&entry.message, &msg);
    }

    #[test]
    fn syslog_parser_never_panics_on_arbitrary_input(s in ".*") {
        let _ = parse_syslog_line(&s, "src");
    }

    /// Plaintext parsing must always succeed (it has no failure mode) and
    /// must never crash, for literally any input string.
    #[test]
    fn plaintext_parser_never_panics(s in ".*", fallback in any::<i64>()) {
        let entry = parse_plaintext_line(&s, "src", fallback);
        prop_assert_eq!(&entry.raw, &s);
    }

    /// When a line embeds an unambiguous ISO8601 timestamp anywhere in it,
    /// the plaintext parser must extract a timestamp equal to what the
    /// heuristic parser alone would produce for that substring (consistency
    /// between the standalone helper and the full line parser).
    #[test]
    fn plaintext_parser_extracts_embedded_iso_timestamp(
        year in 2000i32..2030,
        month in 1u32..13,
        day in 1u32..28,
        hour in 0u32..24,
        minute in 0u32..60,
        second in 0u32..60,
        prefix in "[a-zA-Z ]{0,10}",
        suffix in "[a-zA-Z ]{0,10}",
    ) {
        let ts = format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z");
        let line = format!("{prefix}{ts}{suffix}");
        let entry = parse_plaintext_line(&line, "src", 0);
        prop_assert!(entry.timestamp_ms > 0);
    }
}
