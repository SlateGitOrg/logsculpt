//! End-to-end CLI tests: invoke the actual `logsculpt` binary (via
//! `assert_cmd`) against fixture files and synthetic temp files, exercising
//! the full pipeline (parse -> merge -> anomaly-detect -> output) exactly
//! as a user would from a shell. Fully offline: no network, no Docker.

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::io::Write;

fn fixture_path(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn json_output_merges_and_orders_mixed_formats() {
    let mut cmd = Command::cargo_bin("logsculpt").unwrap();
    let output = cmd
        .arg(fixture_path("mixed.log"))
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.trim_end().split('\n').collect();
    assert_eq!(
        lines.len(),
        11,
        "expected all 11 fixture lines to parse into records"
    );

    let records: Vec<Value> = lines
        .iter()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();

    // Chronological ordering across mixed formats.
    let timestamps: Vec<i64> = records
        .iter()
        .map(|r| r["timestamp_ms"].as_i64().unwrap())
        .collect();
    let mut sorted = timestamps.clone();
    sorted.sort_unstable();
    assert_eq!(timestamps, sorted, "output must be chronologically ordered");

    // Each of the three source formats must be represented.
    let formats: std::collections::HashSet<&str> = records
        .iter()
        .map(|r| r["source_format"].as_str().unwrap())
        .collect();
    assert!(formats.contains("json"));
    // The fixture's syslog lines are RFC 5424 (version "1" after the priority,
    // ISO-8601 timestamp, structured-data field), which the parser classifies
    // as "syslog5424" rather than the legacy BSD "syslog3164".
    assert!(formats.contains("syslog5424"));
    assert!(formats.contains("plaintext"));
}

#[test]
fn csv_output_has_valid_header_and_row_count() {
    let mut cmd = Command::cargo_bin("logsculpt").unwrap();
    let output = cmd
        .arg(fixture_path("mixed.log"))
        .arg("--format")
        .arg("csv")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let mut rdr = csv::Reader::from_reader(stdout.as_bytes());
    let headers = rdr.headers().unwrap().clone();
    assert!(headers.iter().any(|h| h == "timestamp"));
    assert!(headers.iter().any(|h| h == "severity"));
    assert!(headers.iter().any(|h| h == "is_rate_spike"));
    let count = rdr.records().count();
    assert_eq!(count, 11);
}

#[test]
fn invalid_format_flag_errors_cleanly() {
    let mut cmd = Command::cargo_bin("logsculpt").unwrap();
    cmd.arg(fixture_path("mixed.log"))
        .arg("--format")
        .arg("xml")
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown output format"));
}

#[test]
fn missing_file_errors_cleanly_instead_of_panicking() {
    let mut cmd = Command::cargo_bin("logsculpt").unwrap();
    cmd.arg("/nonexistent/path/does-not-exist.log")
        .arg("--format")
        .arg("json")
        .assert()
        .failure();
}

#[test]
fn detects_rare_error_cluster_end_to_end_via_csv() {
    // Build a synthetic log with a clear rare-error burst: a handful of
    // common background errors plus a burst of a distinct, rare error type
    // clustered in a tight window.
    let mut file = tempfile::NamedTempFile::new().unwrap();
    for i in 0..100 {
        writeln!(
            file,
            r#"{{"ts":{},"level":"error","service":"api","message":"cache miss for key {}"}}"#,
            1_700_000_000_000i64 + i * 10_000,
            i
        )
        .unwrap();
    }
    for i in 0..4 {
        writeln!(
            file,
            r#"{{"ts":{},"level":"error","service":"api","message":"tls handshake failed with peer {}"}}"#,
            1_700_000_500_000i64 + i * 500,
            i
        )
        .unwrap();
    }
    file.flush().unwrap();

    let mut cmd = Command::cargo_bin("logsculpt").unwrap();
    let output = cmd
        .arg(file.path())
        .arg("--format")
        .arg("csv")
        .arg("--min-cluster-size")
        .arg("3")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();

    let mut rdr = csv::Reader::from_reader(stdout.as_bytes());
    let headers: Vec<String> = rdr
        .headers()
        .unwrap()
        .iter()
        .map(|s| s.to_string())
        .collect();
    let cluster_col = headers
        .iter()
        .position(|h| h == "is_rare_error_cluster")
        .unwrap();
    let message_col = headers.iter().position(|h| h == "message").unwrap();

    let mut found_flagged_tls_row = false;
    let mut cache_miss_flagged = false;
    for record in rdr.records() {
        let record = record.unwrap();
        let msg = &record[message_col];
        let flagged = &record[cluster_col] == "true";
        if msg.contains("tls handshake") && flagged {
            found_flagged_tls_row = true;
        }
        if msg.contains("cache miss") && flagged {
            cache_miss_flagged = true;
        }
    }
    assert!(
        found_flagged_tls_row,
        "rare tls-handshake burst should be flagged"
    );
    assert!(
        !cache_miss_flagged,
        "common cache-miss error should not be flagged as a rare cluster"
    );
}

#[test]
fn stdin_input_via_dash_is_supported() {
    let mut cmd = Command::cargo_bin("logsculpt").unwrap();
    cmd.arg("-")
        .arg("--format")
        .arg("json")
        .write_stdin("{\"level\":\"info\",\"message\":\"from stdin\"}\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("from stdin"));
}
