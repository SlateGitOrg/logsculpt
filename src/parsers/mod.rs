//! Format dispatch: sniff each line's format and route it to the right
//! parser, normalizing everything into [`crate::schema::LogEntry`].

pub mod json_parser;
pub mod plaintext_parser;
pub mod syslog_parser;

use crate::schema::LogEntry;
use rayon::prelude::*;

/// Parse a single line, auto-detecting its format.
///
/// `fallback_ts_ms` is used only by the plaintext path, for lines with no
/// discoverable timestamp (see [`plaintext_parser::parse_plaintext_line`]).
pub fn parse_line(line: &str, source_name: &str, fallback_ts_ms: i64) -> LogEntry {
    let trimmed = line.trim_end_matches(['\n', '\r']);
    if json_parser::looks_like_json(trimmed) {
        if let Ok(entry) = json_parser::parse_json_line(trimmed, source_name) {
            return entry;
        }
    }
    if syslog_parser::looks_like_syslog(trimmed) {
        if let Ok(entry) = syslog_parser::parse_syslog_line(trimmed, source_name) {
            return entry;
        }
    }
    plaintext_parser::parse_plaintext_line(trimmed, source_name, fallback_ts_ms)
}

/// Parse many lines in parallel with rayon, then restore original order.
///
/// Parsing each line is independent, so this is an embarrassingly-parallel
/// `par_iter().map()` — the workhorse of the "multi-GB throughput" story:
/// splitting a large batch of lines across cores linearizes parse time.
///
/// The plaintext-fallback-timestamp propagation ("carry forward the previous
/// line's timestamp") is inherently sequential, so we do a cheap single pass
/// first to assign fallback timestamps per line based on the nearest prior
/// *complete* timestamp we can find with the fast heuristic regex, then
/// dispatch the actual (more expensive) parsing in parallel.
pub fn parse_lines_parallel(lines: &[String], source_name: &str) -> Vec<LogEntry> {
    let now_ms = crate::time_util::now_utc().timestamp_millis();

    // Sequential pre-pass: cheap timestamp sniff to build fallback values.
    let mut fallbacks = Vec::with_capacity(lines.len());
    let mut last_ts = now_ms;
    for line in lines {
        if let Some(ms) = plaintext_parser::extract_timestamp_ms(line) {
            last_ts = ms;
        }
        fallbacks.push(last_ts);
    }

    lines
        .par_iter()
        .zip(fallbacks.par_iter())
        .map(|(line, fallback)| parse_line(line, source_name, *fallback))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::SourceFormat;

    #[test]
    fn dispatches_json() {
        let entry = parse_line(r#"{"level":"info","message":"hi"}"#, "s", 0);
        assert_eq!(entry.source_format, SourceFormat::Json);
    }

    #[test]
    fn dispatches_syslog() {
        let entry = parse_line("<34>Oct 11 22:14:15 host su: failed", "s", 0);
        assert_eq!(entry.source_format, SourceFormat::SyslogRfc3164);
    }

    #[test]
    fn dispatches_plaintext_fallback() {
        let entry = parse_line("2024-01-15 10:23:45 ERROR something broke", "s", 0);
        assert_eq!(entry.source_format, SourceFormat::PlaintextHeuristic);
    }

    #[test]
    fn malformed_json_looking_line_falls_through_to_plaintext() {
        // Starts with '{' but is not valid JSON -> must not panic, must fall
        // back to plaintext rather than being dropped.
        let entry = parse_line("{not valid json ERROR foo", "s", 0);
        assert_eq!(entry.source_format, SourceFormat::PlaintextHeuristic);
    }

    #[test]
    fn parallel_parse_preserves_order_and_count() {
        let lines: Vec<String> = (0..500)
            .map(|i| {
                format!(
                    r#"{{"ts":{},"level":"info","message":"line {}"}}"#,
                    1_700_000_000_000i64 + i,
                    i
                )
            })
            .collect();
        let entries = parse_lines_parallel(&lines, "bulk.log");
        assert_eq!(entries.len(), 500);
        for (i, e) in entries.iter().enumerate() {
            assert_eq!(e.message, format!("line {i}"));
        }
    }

    #[test]
    fn parallel_parse_propagates_fallback_timestamps_for_plaintext() {
        let lines = vec![
            "2024-01-15 10:23:45 INFO start".to_string(),
            "    continuation line no timestamp".to_string(),
        ];
        let entries = parse_lines_parallel(&lines, "s");
        assert_eq!(entries[0].timestamp_ms, entries[1].timestamp_ms);
    }
}
