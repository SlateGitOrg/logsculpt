//! Small time helpers shared across parsers.

use chrono::{DateTime, Datelike, Local, NaiveDate, NaiveDateTime, TimeZone, Utc};

/// Format epoch milliseconds as an RFC3339 UTC timestamp.
pub fn format_ms_rfc3339(ms: i64) -> String {
    match Utc.timestamp_millis_opt(ms) {
        chrono::LocalResult::Single(dt) => dt.to_rfc3339(),
        _ => "1970-01-01T00:00:00+00:00".to_string(),
    }
}

/// Parse an RFC3339 / ISO8601 timestamp into epoch milliseconds.
pub fn parse_rfc3339_ms(s: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.timestamp_millis())
}

/// Parse a BSD syslog (RFC3164) timestamp, e.g. "Jan  2 15:04:05".
/// RFC3164 has no year, so we infer the most recent past occurrence relative
/// to `now`, matching real syslog daemon behavior (handles December/January
/// wraparound at year boundaries).
pub fn parse_rfc3164_ts(s: &str, now: DateTime<Utc>) -> Option<i64> {
    // Normalize double-space day-of-month ("Jan  2") to single space for chrono.
    let normalized = collapse_spaces(s);
    let with_year_guess = format!("{} {}", now.year(), normalized);
    let parsed = NaiveDateTime::parse_from_str(&with_year_guess, "%Y %b %e %H:%M:%S").ok()?;

    let mut candidate = Utc.from_utc_datetime(&parsed);
    // If the guessed timestamp is more than a day in the future, it must
    // actually belong to last year (e.g. parsing a Dec entry in early Jan).
    if candidate > now + chrono::Duration::days(1) {
        let prev_year = format!("{} {}", now.year() - 1, normalized);
        if let Ok(p) = NaiveDateTime::parse_from_str(&prev_year, "%Y %b %e %H:%M:%S") {
            candidate = Utc.from_utc_datetime(&p);
        }
    }
    Some(candidate.timestamp_millis())
}

fn collapse_spaces(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_space = false;
    for c in s.chars() {
        if c == ' ' {
            if !prev_space {
                out.push(' ');
            }
            prev_space = true;
        } else {
            out.push(c);
            prev_space = false;
        }
    }
    out
}

/// Apache/Common-Log-Format style timestamp: `10/Oct/2000:13:55:36 -0700`.
pub fn parse_clf_ts(s: &str) -> Option<i64> {
    DateTime::parse_from_str(s, "%d/%b/%Y:%H:%M:%S %z")
        .ok()
        .map(|dt| dt.timestamp_millis())
}

/// Best-effort heuristic timestamp extraction used by the plaintext parser
/// and property tests: tries RFC3339, then a handful of common "naive" forms
/// (assumed local, then UTC-normalized), returning `None` if nothing matches.
pub fn heuristic_parse_ts(s: &str) -> Option<i64> {
    if let Some(ms) = parse_rfc3339_ms(s) {
        return Some(ms);
    }
    if let Some(ms) = parse_clf_ts(s) {
        return Some(ms);
    }
    let formats = [
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ];
    for fmt in formats {
        if let Ok(naive) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(Utc.from_utc_datetime(&naive).timestamp_millis());
        }
    }
    // Date-only fallback.
    if let Ok(date) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        let naive = date.and_hms_opt(0, 0, 0)?;
        return Some(Utc.from_utc_datetime(&naive).timestamp_millis());
    }
    None
}

/// Current time — indirection point so tests can be deterministic if needed.
pub fn now_utc() -> DateTime<Utc> {
    Utc::now()
}

#[allow(dead_code)]
pub fn local_now_string() -> String {
    Local::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_roundtrip() {
        let ms = parse_rfc3339_ms("2024-03-15T10:23:45Z").unwrap();
        assert_eq!(format_ms_rfc3339(ms), "2024-03-15T10:23:45+00:00");
    }

    #[test]
    fn rfc3164_infers_year() {
        let now = Utc.with_ymd_and_hms(2024, 6, 15, 12, 0, 0).unwrap();
        let ms = parse_rfc3164_ts("Jun 15 08:00:00", now).unwrap();
        let dt = Utc.timestamp_millis_opt(ms).unwrap();
        assert_eq!(dt.year(), 2024);
        assert_eq!(dt.month(), 6);
        assert_eq!(dt.day(), 15);
    }

    #[test]
    fn rfc3164_year_wraparound() {
        // "now" is early January; a log line timestamped in December must be
        // attributed to the previous year, not the future.
        let now = Utc.with_ymd_and_hms(2024, 1, 2, 0, 30, 0).unwrap();
        let ms = parse_rfc3164_ts("Dec 31 23:50:00", now).unwrap();
        let dt = Utc.timestamp_millis_opt(ms).unwrap();
        assert_eq!(dt.year(), 2023);
    }

    #[test]
    fn clf_timestamp() {
        let ms = parse_clf_ts("10/Oct/2000:13:55:36 -0700").unwrap();
        assert!(ms > 0);
    }

    #[test]
    fn heuristic_naive_datetime() {
        let ms = heuristic_parse_ts("2024-01-15 10:23:45").unwrap();
        let dt = Utc.timestamp_millis_opt(ms).unwrap();
        assert_eq!(dt.year(), 2024);
    }
}
