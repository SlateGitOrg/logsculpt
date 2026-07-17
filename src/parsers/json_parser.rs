//! JSON-lines log parser.
//!
//! Handles the common "structured logging" shape emitted by e.g. bunyan,
//! pino, zap, logrus, and most cloud logging agents: one JSON object per
//! line, with a handful of well-known-but-inconsistently-named fields for
//! timestamp/level/message/service/host.

use crate::schema::{LogEntry, Severity, SourceFormat};
use crate::time_util::heuristic_parse_ts;
use serde_json::Value;
use std::collections::BTreeMap;

const TIMESTAMP_KEYS: &[&str] = &["timestamp", "time", "ts", "@timestamp", "datetime", "date"];
const LEVEL_KEYS: &[&str] = &["level", "severity", "lvl", "loglevel", "log_level"];
const MESSAGE_KEYS: &[&str] = &["message", "msg", "log", "text"];
const SERVICE_KEYS: &[&str] = &["service", "logger", "component", "app", "module", "name"];
const HOST_KEYS: &[&str] = &["host", "hostname", "node", "pod"];

/// Returns `true` if `line` looks like it starts a JSON object/array, cheap
/// enough to call per-line as a format sniff before attempting a full parse.
pub fn looks_like_json(line: &str) -> bool {
    matches!(
        line.trim_start().as_bytes().first(),
        Some(b'{') | Some(b'[')
    )
}

fn first_string_field<'a>(
    obj: &'a serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<&'a str> {
    for k in keys {
        if let Some(v) = obj.get(*k) {
            if let Some(s) = v.as_str() {
                return Some(s);
            }
        }
    }
    None
}

fn extract_timestamp_ms(obj: &serde_json::Map<String, Value>) -> Option<i64> {
    for k in TIMESTAMP_KEYS {
        if let Some(v) = obj.get(*k) {
            match v {
                Value::String(s) => {
                    if let Some(ms) = heuristic_parse_ts(s) {
                        return Some(ms);
                    }
                }
                Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        // Heuristic: values above this threshold are already
                        // milliseconds (year ~2001+ in ms epoch), otherwise
                        // treat as seconds epoch.
                        return Some(if i > 9_999_999_999 { i } else { i * 1000 });
                    }
                    if let Some(f) = n.as_f64() {
                        return Some((f * 1000.0) as i64);
                    }
                }
                _ => {}
            }
        }
    }
    None
}

/// Parse a single JSON-lines record into a normalized [`LogEntry`].
///
/// Returns `Err` with a description if the line is not valid JSON at all;
/// missing individual fields (timestamp, level, etc.) degrade gracefully
/// rather than failing the whole line, since real-world structured logs
/// are rarely 100% schema-complete.
pub fn parse_json_line(line: &str, source_name: &str) -> Result<LogEntry, String> {
    let value: Value = serde_json::from_str(line).map_err(|e| format!("invalid json: {e}"))?;
    let obj = value
        .as_object()
        .ok_or_else(|| "json line is not an object".to_string())?;

    let timestamp_ms =
        extract_timestamp_ms(obj).unwrap_or_else(|| crate::time_util::now_utc().timestamp_millis());

    let severity = first_string_field(obj, LEVEL_KEYS)
        .map(Severity::parse_loose)
        .unwrap_or(Severity::Unknown);

    let message = first_string_field(obj, MESSAGE_KEYS)
        .map(|s| s.to_string())
        .unwrap_or_else(|| line.to_string());

    let service = first_string_field(obj, SERVICE_KEYS).map(|s| s.to_string());
    let host = first_string_field(obj, HOST_KEYS).map(|s| s.to_string());

    let known: std::collections::HashSet<&str> = TIMESTAMP_KEYS
        .iter()
        .chain(LEVEL_KEYS)
        .chain(MESSAGE_KEYS)
        .chain(SERVICE_KEYS)
        .chain(HOST_KEYS)
        .copied()
        .collect();

    let mut fields = BTreeMap::new();
    for (k, v) in obj.iter() {
        if known.contains(k.as_str()) {
            continue;
        }
        let rendered = match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        fields.insert(k.clone(), rendered);
    }

    Ok(LogEntry {
        timestamp_ms,
        severity,
        host,
        service,
        message,
        source_format: SourceFormat::Json,
        source_name: source_name.to_string(),
        fields,
        raw: line.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_well_formed_line() {
        let line = r#"{"timestamp":"2024-03-15T10:23:45Z","level":"error","message":"db timeout","service":"orders-api","host":"host-1","request_id":"abc123"}"#;
        let entry = parse_json_line(line, "app.log").unwrap();
        assert_eq!(entry.severity, Severity::Error);
        assert_eq!(entry.message, "db timeout");
        assert_eq!(entry.service.as_deref(), Some("orders-api"));
        assert_eq!(entry.host.as_deref(), Some("host-1"));
        assert_eq!(entry.fields.get("request_id").unwrap(), "abc123");
        assert_eq!(entry.source_format, SourceFormat::Json);
    }

    #[test]
    fn tolerates_alternate_field_names() {
        let line =
            r#"{"ts":1710498225000,"lvl":"WARN","msg":"disk usage high","logger":"disk-monitor"}"#;
        let entry = parse_json_line(line, "app.log").unwrap();
        assert_eq!(entry.severity, Severity::Warn);
        assert_eq!(entry.message, "disk usage high");
        assert_eq!(entry.service.as_deref(), Some("disk-monitor"));
        assert_eq!(entry.timestamp_ms, 1710498225000);
    }

    #[test]
    fn seconds_epoch_is_upscaled_to_millis() {
        let line = r#"{"ts":1710498225,"msg":"seconds epoch"}"#;
        let entry = parse_json_line(line, "app.log").unwrap();
        assert_eq!(entry.timestamp_ms, 1710498225000);
    }

    #[test]
    fn rejects_non_json() {
        assert!(parse_json_line("not json at all", "app.log").is_err());
    }

    #[test]
    fn rejects_json_array() {
        assert!(parse_json_line("[1,2,3]", "app.log").is_err());
    }

    #[test]
    fn detects_json_sniff() {
        assert!(looks_like_json(r#"{"a":1}"#));
        assert!(looks_like_json("  [1,2]"));
        assert!(!looks_like_json("<13>Jan  2 15:04:05 host tag: hi"));
    }

    #[test]
    fn missing_message_falls_back_to_raw_line() {
        let line = r#"{"level":"info"}"#;
        let entry = parse_json_line(line, "app.log").unwrap();
        assert_eq!(entry.message, line);
    }
}
