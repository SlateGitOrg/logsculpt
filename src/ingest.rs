//! Reads one or more log sources (files or stdin), parses them in parallel,
//! and merges them into a single chronologically-sorted timeline — the
//! "coherent timeline out of mixed inputs" the whole tool exists to build.

use crate::parsers::parse_lines_parallel;
use crate::schema::LogEntry;
use anyhow::{Context, Result};
use rayon::prelude::*;
use std::fs;
use std::io::{self, BufRead, Read};
use std::path::Path;

/// Read a source (a real file path, or `-` for stdin) into raw lines.
pub fn read_lines(path: &str) -> Result<Vec<String>> {
    if path == "-" {
        let stdin = io::stdin();
        let mut lines = Vec::new();
        for line in stdin.lock().lines() {
            lines.push(line.context("reading line from stdin")?);
        }
        Ok(lines)
    } else {
        let content =
            fs::read_to_string(path).with_context(|| format!("reading log file '{path}'"))?;
        Ok(content.lines().map(|s| s.to_string()).collect())
    }
}

/// Read raw bytes and split to lines without requiring valid UTF-8 for the
/// whole file (lossy-converts individual lines that aren't UTF-8, which is
/// common in real-world logs with stray binary data).
pub fn read_lines_lossy(path: &Path) -> Result<Vec<String>> {
    let mut buf = Vec::new();
    fs::File::open(path)
        .with_context(|| format!("opening '{}'", path.display()))?
        .read_to_end(&mut buf)
        .with_context(|| format!("reading '{}'", path.display()))?;
    let text = String::from_utf8_lossy(&buf);
    Ok(text.lines().map(|s| s.to_string()).collect())
}

/// Parse and merge multiple named sources (`(source_name, lines)`) into one
/// sorted timeline. Each source's lines are parsed independently in
/// parallel (both across sources, via `par_iter`, and within a source's
/// lines, via [`parse_lines_parallel`]); the final merge is a single sort
/// over the concatenated, already-normalized entries.
pub fn parse_and_merge(sources: &[(String, Vec<String>)]) -> Vec<LogEntry> {
    let mut all: Vec<LogEntry> = sources
        .par_iter()
        .flat_map(|(name, lines)| parse_lines_parallel(lines, name))
        .collect();
    all.par_sort_unstable();
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_multiple_sources_in_time_order() {
        let sources = vec![
            (
                "service-a.log".to_string(),
                vec![r#"{"ts":"2024-01-01T00:00:03Z","level":"info","message":"a3"}"#.to_string()],
            ),
            (
                "service-b.log".to_string(),
                vec![
                    r#"{"ts":"2024-01-01T00:00:01Z","level":"info","message":"b1"}"#.to_string(),
                    r#"{"ts":"2024-01-01T00:00:02Z","level":"info","message":"b2"}"#.to_string(),
                ],
            ),
        ];
        let merged = parse_and_merge(&sources);
        let messages: Vec<&str> = merged.iter().map(|e| e.message.as_str()).collect();
        assert_eq!(messages, vec!["b1", "b2", "a3"]);
    }

    #[test]
    fn empty_sources_yield_empty_timeline() {
        let merged = parse_and_merge(&[]);
        assert!(merged.is_empty());
    }
}
