//! Syslog parser supporting both the legacy BSD format (RFC 3164) and the
//! modern structured format (RFC 5424).
//!
//! ```text
//! RFC3164: <34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick
//! RFC5424: <165>1 2003-10-11T22:14:15.003Z myhost app - ID47 [ex@32473 x="1"] message body
//! ```

use crate::schema::{LogEntry, Severity, SourceFormat};
use crate::time_util::parse_rfc3164_ts;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::BTreeMap;

// <PRI> at the start of both formats.
static PRI_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^<(\d{1,3})>").unwrap());

// RFC5424: <PRI>VERSION SP TIMESTAMP SP HOST SP APP SP PROCID SP MSGID SP (STRUCTURED-DATA|-) SP? MSG?
static RFC5424_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"^<(?P<pri>\d{1,3})>(?P<ver>\d+)\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?P<sd>(?:-|\[.*?\]))\s?(?P<msg>.*)$",
    )
    .unwrap()
});

// RFC3164: <PRI>Mmm dd hh:mm:ss HOST TAG[PID]?: MSG   (host is optional in the wild)
static RFC3164_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"^<(?P<pri>\d{1,3})>(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<tag>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$",
    )
    .unwrap()
});

fn severity_from_pri(pri: u32) -> Severity {
    let sev = pri % 8;
    Severity::parse_loose(&sev.to_string())
}

pub fn looks_like_syslog(line: &str) -> bool {
    PRI_RE.is_match(line.trim_start())
}

/// Try RFC5424 first (it self-identifies via the `1` version token right
/// after PRI), then fall back to RFC3164.
pub fn parse_syslog_line(line: &str, source_name: &str) -> Result<LogEntry, String> {
    let trimmed = line.trim_start();
    if let Some(caps) = RFC5424_RE.captures(trimmed) {
        return parse_5424(&caps, line, source_name);
    }
    if let Some(caps) = RFC3164_RE.captures(trimmed) {
        return parse_3164(&caps, line, source_name);
    }
    Err("line does not match RFC3164 or RFC5424 syslog grammar".to_string())
}

fn parse_5424(caps: &regex::Captures, raw: &str, source_name: &str) -> Result<LogEntry, String> {
    let pri: u32 = caps["pri"].parse().map_err(|_| "bad PRI".to_string())?;
    let severity = severity_from_pri(pri);
    let ts_str = &caps["ts"];
    let timestamp_ms = crate::time_util::parse_rfc3339_ms(ts_str)
        .ok_or_else(|| format!("bad RFC5424 timestamp: {ts_str}"))?;
    let host = normalize_nil(&caps["host"]);
    let app = normalize_nil(&caps["app"]);
    let msg = caps["msg"].to_string();

    let mut fields = BTreeMap::new();
    if let Some(procid) = normalize_nil(&caps["procid"]) {
        fields.insert("procid".to_string(), procid);
    }
    if let Some(msgid) = normalize_nil(&caps["msgid"]) {
        fields.insert("msgid".to_string(), msgid);
    }
    let sd = &caps["sd"];
    if sd != "-" {
        fields.insert("structured_data".to_string(), sd.to_string());
    }

    Ok(LogEntry {
        timestamp_ms,
        severity,
        host,
        service: app,
        message: msg,
        source_format: SourceFormat::SyslogRfc5424,
        source_name: source_name.to_string(),
        fields,
        raw: raw.to_string(),
    })
}

fn parse_3164(caps: &regex::Captures, raw: &str, source_name: &str) -> Result<LogEntry, String> {
    let pri: u32 = caps["pri"].parse().map_err(|_| "bad PRI".to_string())?;
    let severity = severity_from_pri(pri);
    let ts_str = &caps["ts"];
    let timestamp_ms = parse_rfc3164_ts(ts_str, crate::time_util::now_utc())
        .ok_or_else(|| format!("bad RFC3164 timestamp: {ts_str}"))?;
    let host = Some(caps["host"].to_string());
    let tag = Some(caps["tag"].to_string());
    let msg = caps["msg"].to_string();

    let mut fields = BTreeMap::new();
    if let Some(pid) = caps.name("pid") {
        fields.insert("pid".to_string(), pid.as_str().to_string());
    }

    Ok(LogEntry {
        timestamp_ms,
        severity,
        host,
        service: tag,
        message: msg,
        source_format: SourceFormat::SyslogRfc3164,
        source_name: source_name.to_string(),
        fields,
        raw: raw.to_string(),
    })
}

fn normalize_nil(s: &str) -> Option<String> {
    if s == "-" {
        None
    } else {
        Some(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rfc3164() {
        let line = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8";
        let entry = parse_syslog_line(line, "sys.log").unwrap();
        assert_eq!(entry.source_format, SourceFormat::SyslogRfc3164);
        assert_eq!(entry.host.as_deref(), Some("mymachine"));
        assert_eq!(entry.service.as_deref(), Some("su"));
        assert_eq!(entry.message, "'su root' failed for lonvick on /dev/pts/8");
        // pri 34 = facility 4, severity 2 -> Critical
        assert_eq!(entry.severity, Severity::Critical);
    }

    #[test]
    fn parses_rfc3164_with_pid() {
        let line = "<13>Jan  2 15:04:05 web-1 nginx[4321]: 500 Internal Server Error";
        let entry = parse_syslog_line(line, "sys.log").unwrap();
        assert_eq!(entry.service.as_deref(), Some("nginx"));
        assert_eq!(entry.fields.get("pid").unwrap(), "4321");
        assert_eq!(entry.message, "500 Internal Server Error");
    }

    #[test]
    fn parses_rfc5424() {
        let line = r#"<165>1 2003-10-11T22:14:15.003Z myhost.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application"] An application event log entry"#;
        let entry = parse_syslog_line(line, "sys.log").unwrap();
        assert_eq!(entry.source_format, SourceFormat::SyslogRfc5424);
        assert_eq!(entry.host.as_deref(), Some("myhost.example.com"));
        assert_eq!(entry.service.as_deref(), Some("evntslog"));
        assert_eq!(entry.message, "An application event log entry");
        assert_eq!(entry.fields.get("msgid").unwrap(), "ID47");
        assert!(entry.fields.contains_key("structured_data"));
    }

    #[test]
    fn parses_rfc5424_nil_structured_data() {
        let line = "<165>1 2003-10-11T22:14:15.003Z myhost app 1234 - - hello world";
        let entry = parse_syslog_line(line, "sys.log").unwrap();
        assert_eq!(entry.fields.get("procid").unwrap(), "1234");
        assert!(!entry.fields.contains_key("structured_data"));
        assert_eq!(entry.message, "hello world");
    }

    #[test]
    fn severity_maps_from_pri_correctly() {
        // pri 13 = facility 1 (user), severity 5 (notice)
        let line = "<13>Jan  2 15:04:05 host tag: msg";
        let entry = parse_syslog_line(line, "s").unwrap();
        assert_eq!(entry.severity, Severity::Notice);
    }

    #[test]
    fn rejects_non_syslog() {
        assert!(parse_syslog_line("plain text with no PRI header", "s").is_err());
        assert!(parse_syslog_line(r#"{"a":1}"#, "s").is_err());
    }

    #[test]
    fn sniff_detects_pri_header() {
        assert!(looks_like_syslog("<34>Oct 11 22:14:15 host tag: msg"));
        assert!(!looks_like_syslog("no pri header here"));
    }
}
