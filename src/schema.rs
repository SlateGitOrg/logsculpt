//! Common normalized log schema.
//!
//! Every parser (JSON, syslog, plaintext-heuristic) produces a [`LogEntry`],
//! regardless of the wire format it came from. This is the "coherent timeline"
//! abstraction the rest of the tool (anomaly detection, TUI, json/csv output)
//! is built on top of.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

/// Normalized severity level, ordered from least to most severe.
///
/// Derives `PartialOrd`/`Ord` from declaration order so `Severity::Error > Severity::Info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Trace,
    Debug,
    Info,
    Notice,
    Warn,
    Error,
    Critical,
    Unknown,
}

impl Severity {
    /// Best-effort classification from a free-form level token
    /// (e.g. "WARNING", "err", "crit", "5" syslog severity digit).
    pub fn parse_loose(raw: &str) -> Severity {
        let s = raw.trim().to_ascii_lowercase();
        match s.as_str() {
            "trace" | "tr" => Severity::Trace,
            "debug" | "dbg" | "7" => Severity::Debug,
            "info" | "information" | "informational" | "6" => Severity::Info,
            "notice" | "5" => Severity::Notice,
            "warn" | "warning" | "4" => Severity::Warn,
            "error" | "err" | "3" => Severity::Error,
            "critical" | "crit" | "fatal" | "panic" | "emerg" | "emergency" | "alert" | "0"
            | "1" | "2" => Severity::Critical,
            _ => Severity::Unknown,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Trace => "TRACE",
            Severity::Debug => "DEBUG",
            Severity::Info => "INFO",
            Severity::Notice => "NOTICE",
            Severity::Warn => "WARN",
            Severity::Error => "ERROR",
            Severity::Critical => "CRITICAL",
            Severity::Unknown => "UNKNOWN",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Which parser produced this entry. Kept around for debugging / audit trails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceFormat {
    Json,
    SyslogRfc3164,
    SyslogRfc5424,
    PlaintextHeuristic,
}

impl fmt::Display for SourceFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            SourceFormat::Json => "json",
            SourceFormat::SyslogRfc3164 => "syslog3164",
            SourceFormat::SyslogRfc5424 => "syslog5424",
            SourceFormat::PlaintextHeuristic => "plaintext",
        };
        write!(f, "{s}")
    }
}

/// A single normalized log record, regardless of source format.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogEntry {
    /// Milliseconds since Unix epoch (UTC). Chosen over `DateTime<Utc>` directly
    /// in the schema so entries serialize as plain integers in json/csv output
    /// and remain trivially `Ord`/`Copy`-cheap for sorting/bucketing.
    pub timestamp_ms: i64,
    pub severity: Severity,
    pub host: Option<String>,
    pub service: Option<String>,
    pub message: String,
    pub source_format: SourceFormat,
    /// Which input file/stream this came from (for multi-file merges).
    pub source_name: String,
    /// Any additional structured fields captured from JSON logs.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
    /// Original raw line, preserved for the TUI detail view / audits.
    pub raw: String,
}

impl LogEntry {
    /// RFC3339 rendering of `timestamp_ms`, used for display and CSV/JSON output.
    pub fn timestamp_rfc3339(&self) -> String {
        crate::time_util::format_ms_rfc3339(self.timestamp_ms)
    }
}

// Order entries by time first (this is what makes "a coherent timeline" possible
// when merging streams from many services), then by service/host as a tiebreaker
// so the ordering is fully deterministic (needed for stable sort in tests/TUI).
impl PartialOrd for LogEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for LogEntry {}

impl Ord for LogEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.timestamp_ms
            .cmp(&other.timestamp_ms)
            .then_with(|| self.source_name.cmp(&other.source_name))
            .then_with(|| self.raw.cmp(&other.raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Error > Severity::Info);
        assert!(Severity::Critical > Severity::Error);
        assert!(Severity::Trace < Severity::Debug);
    }

    #[test]
    fn severity_loose_parsing() {
        assert_eq!(Severity::parse_loose("WARNING"), Severity::Warn);
        assert_eq!(Severity::parse_loose("err"), Severity::Error);
        assert_eq!(Severity::parse_loose("fatal"), Severity::Critical);
        assert_eq!(Severity::parse_loose("bogus"), Severity::Unknown);
    }

    #[test]
    fn entries_sort_by_timestamp() {
        let mk = |ts: i64, raw: &str| LogEntry {
            timestamp_ms: ts,
            severity: Severity::Info,
            host: None,
            service: None,
            message: raw.to_string(),
            source_format: SourceFormat::PlaintextHeuristic,
            source_name: "a".to_string(),
            fields: BTreeMap::new(),
            raw: raw.to_string(),
        };
        let mut v = [mk(300, "c"), mk(100, "a"), mk(200, "b")];
        v.sort();
        let ts: Vec<i64> = v.iter().map(|e| e.timestamp_ms).collect();
        assert_eq!(ts, vec![100, 200, 300]);
    }
}
