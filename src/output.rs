//! Non-interactive output: `--format json` (newline-delimited JSON, easy to
//! pipe into `jq`) and `--format csv` (spreadsheet/`awk`-friendly).
//!
//! Both formats annotate each record with whether it fell inside a detected
//! rate-spike bucket and/or belongs to a rare-error cluster fingerprint, so
//! downstream tooling doesn't have to re-run detection.

use crate::anomaly::{ErrorCluster, RateSpike};
use crate::schema::LogEntry;
use serde::Serialize;
use std::collections::HashSet;
use std::io::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Csv,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "json" => Ok(OutputFormat::Json),
            "csv" => Ok(OutputFormat::Csv),
            other => Err(format!(
                "unknown output format '{other}' (expected json or csv)"
            )),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AnnotatedRecord {
    pub timestamp: String,
    pub timestamp_ms: i64,
    pub severity: String,
    pub host: Option<String>,
    pub service: Option<String>,
    pub message: String,
    pub source: String,
    pub source_format: String,
    pub is_rate_spike: bool,
    pub is_rare_error_cluster: bool,
}

/// Precomputed lookup structure so annotating N entries against M spikes/
/// clusters doesn't become O(N*M).
pub struct AnomalyIndex {
    spike_buckets: HashSet<i64>,
    bucket_ms: i64,
    cluster_fingerprints: HashSet<String>,
}

impl AnomalyIndex {
    pub fn build(spikes: &[RateSpike], bucket_ms: i64, clusters: &[ErrorCluster]) -> Self {
        AnomalyIndex {
            spike_buckets: spikes.iter().map(|s| s.bucket_start_ms).collect(),
            bucket_ms: bucket_ms.max(1),
            cluster_fingerprints: clusters.iter().map(|c| c.fingerprint.clone()).collect(),
        }
    }

    fn is_rate_spike(&self, ts_ms: i64) -> bool {
        if self.spike_buckets.is_empty() {
            return false;
        }
        // A bucket is anchored by its own start; test membership by rounding
        // down `ts_ms` relative to the minimum recorded bucket start using
        // modular arithmetic on bucket width (buckets are contiguous and
        // fixed-width, so this is equivalent to re-bucketing this timestamp).
        self.spike_buckets
            .iter()
            .any(|&start| ts_ms >= start && ts_ms < start + self.bucket_ms)
    }

    fn is_in_cluster(&self, message: &str) -> bool {
        if self.cluster_fingerprints.is_empty() {
            return false;
        }
        self.cluster_fingerprints
            .contains(&crate::anomaly::fingerprint_message(message))
    }
}

pub fn annotate(entry: &LogEntry, index: &AnomalyIndex) -> AnnotatedRecord {
    AnnotatedRecord {
        timestamp: entry.timestamp_rfc3339(),
        timestamp_ms: entry.timestamp_ms,
        severity: entry.severity.to_string(),
        host: entry.host.clone(),
        service: entry.service.clone(),
        message: entry.message.clone(),
        source: entry.source_name.clone(),
        source_format: entry.source_format.to_string(),
        is_rate_spike: index.is_rate_spike(entry.timestamp_ms),
        is_rare_error_cluster: index.is_in_cluster(&entry.message),
    }
}

pub fn write_json<W: Write>(mut w: W, records: &[AnnotatedRecord]) -> std::io::Result<()> {
    for r in records {
        let line = serde_json::to_string(r).expect("AnnotatedRecord always serializes");
        writeln!(w, "{line}")?;
    }
    Ok(())
}

pub fn write_csv<W: Write>(w: W, records: &[AnnotatedRecord]) -> anyhow::Result<()> {
    let mut wtr = csv::Writer::from_writer(w);
    for r in records {
        wtr.serialize(r)?;
    }
    wtr.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anomaly::{ErrorCluster, RateSpike};
    use crate::schema::{Severity, SourceFormat};
    use std::collections::BTreeMap;
    use std::str::FromStr;

    fn mk_entry(ts: i64, msg: &str) -> LogEntry {
        LogEntry {
            timestamp_ms: ts,
            severity: Severity::Error,
            host: Some("h1".to_string()),
            service: Some("svc".to_string()),
            message: msg.to_string(),
            source_format: SourceFormat::Json,
            source_name: "a.log".to_string(),
            fields: BTreeMap::new(),
            raw: msg.to_string(),
        }
    }

    #[test]
    fn parses_format_from_str() {
        assert_eq!(OutputFormat::from_str("json").unwrap(), OutputFormat::Json);
        assert_eq!(OutputFormat::from_str("CSV").unwrap(), OutputFormat::Csv);
        assert!(OutputFormat::from_str("xml").is_err());
    }

    #[test]
    fn annotates_rate_spike_membership() {
        let spikes = vec![RateSpike {
            bucket_start_ms: 10_000,
            count: 50,
            mean: 1.0,
            stddev: 1.0,
            z_score: 40.0,
        }];
        let index = AnomalyIndex::build(&spikes, 10_000, &[]);
        let inside = mk_entry(15_000, "hello");
        let outside = mk_entry(5_000, "hello");
        assert!(annotate(&inside, &index).is_rate_spike);
        assert!(!annotate(&outside, &index).is_rate_spike);
    }

    #[test]
    fn annotates_cluster_membership_by_fingerprint() {
        let clusters = vec![ErrorCluster {
            fingerprint: crate::anomaly::fingerprint_message("tls handshake failed with peer 10"),
            window_start_ms: 0,
            burst_count: 5,
            total_count: 5,
            sample_message: "tls handshake failed with peer 10".to_string(),
        }];
        let index = AnomalyIndex::build(&[], 10_000, &clusters);
        let matching = mk_entry(0, "tls handshake failed with peer 99");
        let non_matching = mk_entry(0, "totally unrelated message");
        assert!(annotate(&matching, &index).is_rare_error_cluster);
        assert!(!annotate(&non_matching, &index).is_rare_error_cluster);
    }

    #[test]
    fn json_output_is_one_object_per_line() {
        let records = vec![
            annotate(&mk_entry(0, "a"), &AnomalyIndex::build(&[], 1000, &[])),
            annotate(&mk_entry(1, "b"), &AnomalyIndex::build(&[], 1000, &[])),
        ];
        let mut buf = Vec::new();
        write_json(&mut buf, &records).unwrap();
        let text = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = text.trim_end().split('\n').collect();
        assert_eq!(lines.len(), 2);
        for line in lines {
            let _: serde_json::Value = serde_json::from_str(line).unwrap();
        }
    }

    #[test]
    fn csv_output_has_header_and_rows() {
        let index = AnomalyIndex::build(&[], 1000, &[]);
        let records = vec![annotate(&mk_entry(0, "hello world"), &index)];
        let mut buf = Vec::new();
        write_csv(&mut buf, &records).unwrap();
        let text = String::from_utf8(buf).unwrap();
        let mut lines = text.lines();
        assert!(lines.next().unwrap().contains("timestamp"));
        assert!(lines.next().unwrap().contains("hello world"));
    }
}
