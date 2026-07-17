//! Statistical anomaly detection over a normalized timeline — no external ML
//! dependency, just two classic, cheap-to-explain-on-a-postmortem-call
//! techniques:
//!
//! 1. **Rate spikes**: bucket the timeline into fixed windows, flag buckets
//!    whose event count is an outlier (z-score) relative to the rest of the
//!    stream. Good for "something started logging way more than usual".
//! 2. **Rare-error clustering**: fingerprint error/critical messages (strip
//!    volatile bits like ids/numbers), then flag fingerprints that are
//!    globally rare but suddenly burst within a short window. Good for
//!    "a *new kind* of error just started happening repeatedly", which a
//!    pure rate-spike detector misses if overall error volume is normal.

use crate::schema::{LogEntry, Severity};
use once_cell::sync::Lazy;
use rayon::prelude::*;
use regex::Regex;
use std::collections::{BTreeMap, HashMap};

// ---------------------------------------------------------------------
// Rate spike detection
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct RateSpikeConfig {
    /// Width of each time bucket, in milliseconds.
    pub bucket_ms: i64,
    /// How many standard deviations above the mean counts as a spike.
    pub z_threshold: f64,
    /// Minimum absolute count for a bucket to ever be flagged, so a jump
    /// from 0 events/bucket to 2 events/bucket on an otherwise-silent
    /// service doesn't register as a statistically "infinite" spike.
    pub min_count: usize,
}

impl Default for RateSpikeConfig {
    fn default() -> Self {
        RateSpikeConfig {
            bucket_ms: 10_000,
            z_threshold: 3.0,
            min_count: 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RateSpike {
    pub bucket_start_ms: i64,
    pub count: usize,
    pub mean: f64,
    pub stddev: f64,
    pub z_score: f64,
}

/// Bucket entries by timestamp and compute per-bucket counts in parallel
/// (map-reduce over chunks: each chunk builds a partial `BTreeMap`, chunks
/// are merged pairwise). Buckets with zero events are included explicitly
/// (dense range from min to max bucket) so the mean/stddev reflect real
/// silence, not just "buckets that happened to contain something".
fn bucket_counts(entries: &[LogEntry], bucket_ms: i64) -> BTreeMap<i64, usize> {
    if entries.is_empty() || bucket_ms <= 0 {
        return BTreeMap::new();
    }
    let min_ts = entries.iter().map(|e| e.timestamp_ms).min().unwrap();
    let max_ts = entries.iter().map(|e| e.timestamp_ms).max().unwrap();

    let sparse: BTreeMap<i64, usize> = entries
        .par_iter()
        .fold(BTreeMap::new, |mut acc, e| {
            let bucket = (e.timestamp_ms - min_ts) / bucket_ms;
            *acc.entry(bucket).or_insert(0) += 1;
            acc
        })
        .reduce(BTreeMap::new, |mut a, b| {
            for (k, v) in b {
                *a.entry(k).or_insert(0) += v;
            }
            a
        });

    let max_bucket = (max_ts - min_ts) / bucket_ms;
    let mut dense = BTreeMap::new();
    for b in 0..=max_bucket {
        let count = sparse.get(&b).copied().unwrap_or(0);
        dense.insert(min_ts + b * bucket_ms, count);
    }
    dense
}

/// Detect time buckets whose event count is a statistical outlier.
pub fn detect_rate_spikes(entries: &[LogEntry], config: &RateSpikeConfig) -> Vec<RateSpike> {
    let counts = bucket_counts(entries, config.bucket_ms);
    if counts.len() < 2 {
        return Vec::new();
    }

    let n = counts.len() as f64;
    let sum: f64 = counts.values().map(|&c| c as f64).sum();
    let mean = sum / n;
    let variance = counts
        .values()
        .map(|&c| (c as f64 - mean).powi(2))
        .sum::<f64>()
        / n;
    let stddev = variance.sqrt();

    if stddev == 0.0 {
        return Vec::new();
    }

    counts
        .into_iter()
        .filter_map(|(bucket_start_ms, count)| {
            let z = (count as f64 - mean) / stddev;
            if z >= config.z_threshold && count >= config.min_count {
                Some(RateSpike {
                    bucket_start_ms,
                    count,
                    mean,
                    stddev,
                    z_score: z,
                })
            } else {
                None
            }
        })
        .collect()
}

// ---------------------------------------------------------------------
// Rare-error clustering
// ---------------------------------------------------------------------

static NUM_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\d+").unwrap());
static HEX_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\b0x[0-9a-f]+\b").unwrap());
static UUID_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b").unwrap()
});
static QUOTED_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"'[^']*'|"[^"]*""#).unwrap());

/// Collapse the volatile parts of an error message (ids, numbers, quoted
/// values) so that structurally-identical errors with different payloads
/// ("user 42 not found" / "user 99 not found") map to the same fingerprint.
pub fn fingerprint_message(message: &str) -> String {
    let s = UUID_RE.replace_all(message, "<uuid>");
    let s = HEX_RE.replace_all(&s, "<hex>");
    let s = QUOTED_RE.replace_all(&s, "<str>");
    let s = NUM_RE.replace_all(&s, "#");
    s.trim().to_string()
}

#[derive(Debug, Clone, Copy)]
pub struct ErrorClusterConfig {
    /// Sliding window width, in milliseconds, used to detect bursts.
    pub window_ms: i64,
    /// A fingerprint is "rare" if it makes up no more than this fraction of
    /// total error-level volume.
    pub rare_ratio: f64,
    /// Minimum occurrences within `window_ms` to call it a cluster.
    pub min_cluster_size: usize,
}

impl Default for ErrorClusterConfig {
    fn default() -> Self {
        ErrorClusterConfig {
            window_ms: 60_000,
            rare_ratio: 0.05,
            min_cluster_size: 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ErrorCluster {
    pub fingerprint: String,
    pub window_start_ms: i64,
    pub burst_count: usize,
    pub total_count: usize,
    pub sample_message: String,
}

/// Find the maximum number of timestamps (from a sorted slice) that fall
/// within any `window_ms`-wide window, via the classic two-pointer sweep.
/// Returns `(max_count, window_start_ms_of_best_window)`.
fn max_window_count(sorted_ts: &[i64], window_ms: i64) -> (usize, i64) {
    let mut left = 0usize;
    let mut best = (0usize, sorted_ts.first().copied().unwrap_or(0));
    for right in 0..sorted_ts.len() {
        while sorted_ts[right] - sorted_ts[left] > window_ms {
            left += 1;
        }
        let count = right - left + 1;
        if count > best.0 {
            best = (count, sorted_ts[left]);
        }
    }
    best
}

/// Detect fingerprints of error/critical messages that are globally rare but
/// burst within a short window — signaling a *new* failure mode rather than
/// ordinary background error noise.
pub fn detect_rare_error_clusters(
    entries: &[LogEntry],
    config: &ErrorClusterConfig,
) -> Vec<ErrorCluster> {
    let errors: Vec<&LogEntry> = entries
        .iter()
        .filter(|e| e.severity >= Severity::Error)
        .collect();
    if errors.is_empty() {
        return Vec::new();
    }

    // Fingerprinting is the expensive regex-heavy step: parallelize it.
    let fingerprints: Vec<String> = errors
        .par_iter()
        .map(|e| fingerprint_message(&e.message))
        .collect();

    let total_errors = errors.len();
    let mut groups: HashMap<&str, (Vec<i64>, &str)> = HashMap::new();
    for (entry, fp) in errors.iter().zip(fingerprints.iter()) {
        let g = groups
            .entry(fp.as_str())
            .or_insert_with(|| (Vec::new(), entry.message.as_str()));
        g.0.push(entry.timestamp_ms);
    }

    let mut clusters: Vec<ErrorCluster> = groups
        .into_iter()
        .filter_map(|(fp, (mut timestamps, sample))| {
            let total_count = timestamps.len();
            let ratio = total_count as f64 / total_errors as f64;
            if ratio > config.rare_ratio {
                return None; // too common to be "a rare error cluster"
            }
            timestamps.sort_unstable();
            let (burst_count, window_start_ms) = max_window_count(&timestamps, config.window_ms);
            if burst_count >= config.min_cluster_size {
                Some(ErrorCluster {
                    fingerprint: fp.to_string(),
                    window_start_ms,
                    burst_count,
                    total_count,
                    sample_message: sample.to_string(),
                })
            } else {
                None
            }
        })
        .collect();

    clusters.sort_by(|a, b| {
        b.burst_count
            .cmp(&a.burst_count)
            .then_with(|| a.window_start_ms.cmp(&b.window_start_ms))
    });
    clusters
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::SourceFormat;
    use std::collections::BTreeMap as BMap;

    fn mk(ts: i64, severity: Severity, msg: &str) -> LogEntry {
        LogEntry {
            timestamp_ms: ts,
            severity,
            host: None,
            service: None,
            message: msg.to_string(),
            source_format: SourceFormat::PlaintextHeuristic,
            source_name: "t".to_string(),
            fields: BMap::new(),
            raw: msg.to_string(),
        }
    }

    #[test]
    fn fingerprint_collapses_numbers_and_ids() {
        let a = fingerprint_message("user 42 not found in region eu-1");
        let b = fingerprint_message("user 9081 not found in region eu-1");
        assert_eq!(a, b);
    }

    #[test]
    fn fingerprint_collapses_uuids_and_quoted_strings() {
        let a =
            fingerprint_message("failed request 'abc-123' id=550e8400-e29b-41d4-a716-446655440000");
        let b =
            fingerprint_message("failed request 'xyz-999' id=6ba7b810-9dad-11d1-80b4-00c04fd430c8");
        assert_eq!(a, b);
    }

    #[test]
    fn detects_rate_spike() {
        let mut entries = Vec::new();
        // Quiet baseline: 1 event every 10s bucket for 20 buckets.
        for i in 0..20 {
            entries.push(mk(i * 10_000, Severity::Info, "heartbeat"));
        }
        // Spike bucket: 50 events crammed into one bucket.
        for i in 0..50 {
            entries.push(mk(200_000 + i, Severity::Error, "burst"));
        }
        let spikes = detect_rate_spikes(&entries, &RateSpikeConfig::default());
        assert!(
            !spikes.is_empty(),
            "expected at least one spike to be detected"
        );
        assert!(spikes.iter().any(|s| s.bucket_start_ms == 200_000));
    }

    #[test]
    fn no_spikes_on_uniform_traffic() {
        let entries: Vec<LogEntry> = (0..100)
            .map(|i| mk(i * 1_000, Severity::Info, "steady"))
            .collect();
        let spikes = detect_rate_spikes(&entries, &RateSpikeConfig::default());
        assert!(spikes.is_empty());
    }

    #[test]
    fn detects_rare_error_cluster() {
        let mut entries = Vec::new();
        // Common background error: 100 occurrences spread out (not rare).
        for i in 0..100 {
            entries.push(mk(i * 10_000, Severity::Error, "cache miss for key 42"));
        }
        // Rare new error type bursting 5 times within 10s.
        for i in 0..5 {
            entries.push(mk(
                1_000_000 + i * 1000,
                Severity::Error,
                "tls handshake failed with peer 10",
            ));
        }
        let clusters = detect_rare_error_clusters(&entries, &ErrorClusterConfig::default());
        assert!(clusters
            .iter()
            .any(|c| c.fingerprint.contains("tls handshake failed")));
        // The common cache-miss message must NOT be flagged (it's >5% of total volume).
        assert!(!clusters
            .iter()
            .any(|c| c.fingerprint.contains("cache miss")));
    }

    #[test]
    fn ignores_non_error_severities() {
        let entries: Vec<LogEntry> = (0..10)
            .map(|i| mk(i * 1000, Severity::Info, "just chatting"))
            .collect();
        let clusters = detect_rare_error_clusters(&entries, &ErrorClusterConfig::default());
        assert!(clusters.is_empty());
    }

    #[test]
    fn max_window_count_finds_densest_window() {
        let ts = vec![0, 1000, 2000, 100_000, 100_500];
        let (count, start) = max_window_count(&ts, 5_000);
        assert_eq!(count, 3);
        assert_eq!(start, 0);
    }
}
