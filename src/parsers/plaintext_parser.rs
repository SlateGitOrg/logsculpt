//! Heuristic plaintext parser: the fallback for logs that are neither JSON
//! nor syslog. Scans the line for a recognizable timestamp pattern and a
//! severity keyword anywhere in the text, since ad-hoc application logs put
//! these in wildly inconsistent positions (`[2024-01-15 10:23:45] ERROR ...`,
//! `ERROR: 2024-01-15T10:23:45Z ...`, `10.23.45 [ERROR] ...`).

use crate::schema::{LogEntry, Severity, SourceFormat};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::BTreeMap;

// Ordered by specificity: try the most unambiguous patterns first.
static TS_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // ISO8601 / RFC3339, with optional fractional seconds and Z/offset.
        Regex::new(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")
            .unwrap(),
        // Common Log Format: 10/Oct/2000:13:55:36 -0700
        Regex::new(r"\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4}").unwrap(),
        // Slash date: 2024/01/15 10:23:45
        Regex::new(r"\d{4}/\d{2}/\d{2}\s\d{2}:\d{2}:\d{2}").unwrap(),
        // US date: 01/15/2024 10:23:45
        Regex::new(r"\d{2}/\d{2}/\d{4}\s\d{2}:\d{2}:\d{2}").unwrap(),
        // Date only: 2024-01-15
        Regex::new(r"\d{4}-\d{2}-\d{2}").unwrap(),
    ]
});

static SEVERITY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(TRACE|DEBUG|INFO(?:RMATION)?|NOTICE|WARN(?:ING)?|ERROR|ERR|FATAL|CRITICAL|CRIT|PANIC|EMERG(?:ENCY)?|ALERT)\b")
        .unwrap()
});

// `service[123]:` or `service:` style prefix, common in app logs that mimic
// syslog conventions without a PRI header.
static SERVICE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\s*(?P<svc>[A-Za-z0-9_.\-]+)(?:\[\d+\])?:\s").unwrap());

pub fn extract_timestamp_ms(line: &str) -> Option<i64> {
    for pattern in TS_PATTERNS.iter() {
        if let Some(m) = pattern.find(line) {
            if let Some(ms) = crate::time_util::heuristic_parse_ts(m.as_str()) {
                return Some(ms);
            }
        }
    }
    None
}

pub fn extract_severity(line: &str) -> Severity {
    SEVERITY_RE
        .find(line)
        .map(|m| Severity::parse_loose(m.as_str()))
        .unwrap_or(Severity::Unknown)
}

/// Parse an arbitrary plaintext log line. This parser never hard-fails: if no
/// timestamp is found, the caller-supplied `fallback_ts_ms` is used (normally
/// "now", or the previous line's timestamp when scanning a stream, so a
/// timestamp-less continuation line still lands in roughly the right place
/// on the timeline).
pub fn parse_plaintext_line(line: &str, source_name: &str, fallback_ts_ms: i64) -> LogEntry {
    let timestamp_ms = extract_timestamp_ms(line).unwrap_or(fallback_ts_ms);
    let severity = extract_severity(line);
    let service = SERVICE_RE.captures(line).map(|c| c["svc"].to_string());

    LogEntry {
        timestamp_ms,
        severity,
        host: None,
        service,
        message: line.to_string(),
        source_format: SourceFormat::PlaintextHeuristic,
        source_name: source_name.to_string(),
        fields: BTreeMap::new(),
        raw: line.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_iso_timestamp_and_level() {
        let line = "[2024-01-15 10:23:45] ERROR payment-service: card declined";
        let entry = parse_plaintext_line(line, "app.log", 0);
        assert_eq!(entry.severity, Severity::Error);
        assert!(entry.timestamp_ms > 0);
    }

    #[test]
    fn extracts_service_prefix() {
        let line = "payment-service[812]: card declined for user 42";
        let entry = parse_plaintext_line(line, "app.log", 0);
        assert_eq!(entry.service.as_deref(), Some("payment-service"));
    }

    #[test]
    fn extracts_clf_style_timestamp() {
        let line = r#"127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html" 200"#;
        let ms = extract_timestamp_ms(line).unwrap();
        assert!(ms > 0);
    }

    #[test]
    fn falls_back_to_supplied_timestamp_when_absent() {
        let line = "    continued output with no timestamp or level keyword";
        let entry = parse_plaintext_line(line, "app.log", 12345);
        assert_eq!(entry.timestamp_ms, 12345);
        assert_eq!(entry.severity, Severity::Unknown);
    }

    #[test]
    fn case_insensitive_severity_keywords() {
        assert_eq!(extract_severity("something warning: disk"), Severity::Warn);
        assert_eq!(extract_severity("FATAL: crash"), Severity::Critical);
        assert_eq!(extract_severity("nothing interesting"), Severity::Unknown);
    }
}
