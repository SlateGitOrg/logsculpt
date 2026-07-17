use anyhow::Result;
use clap::Parser;
use logsculpt::anomaly::{
    detect_rare_error_clusters, detect_rate_spikes, ErrorClusterConfig, RateSpikeConfig,
};
use logsculpt::ingest::{parse_and_merge, read_lines};
use logsculpt::output::{annotate, write_csv, write_json, AnomalyIndex, OutputFormat};
use logsculpt::tui::{run, TuiApp};
use std::io;
use std::str::FromStr;

/// logsculpt: merge mixed-format logs (JSON/syslog/plaintext) into one
/// coherent, anomaly-annotated timeline.
#[derive(Parser, Debug)]
#[command(name = "logsculpt", version, about, long_about = None)]
struct Cli {
    /// Log files to ingest. Use "-" to read from stdin. Multiple files are
    /// merged into a single chronological timeline.
    #[arg(required = true)]
    files: Vec<String>,

    /// Non-interactive output format. If omitted, launches the interactive
    /// TUI timeline viewer instead.
    #[arg(long, value_name = "json|csv")]
    format: Option<String>,

    /// Rate-spike bucket width, in milliseconds.
    #[arg(long, default_value_t = 10_000)]
    bucket_ms: i64,

    /// Z-score threshold above which a bucket is flagged as a rate spike.
    #[arg(long, default_value_t = 3.0)]
    z_threshold: f64,

    /// Minimum event count for a bucket to ever be flagged as a spike.
    #[arg(long, default_value_t = 5)]
    min_spike_count: usize,

    /// Sliding window width for rare-error clustering, in milliseconds.
    #[arg(long, default_value_t = 60_000)]
    cluster_window_ms: i64,

    /// A fingerprint is "rare" if it's at most this fraction of total error volume.
    #[arg(long, default_value_t = 0.05)]
    rare_ratio: f64,

    /// Minimum burst size within the cluster window to flag a rare-error cluster.
    #[arg(long, default_value_t = 3)]
    min_cluster_size: usize,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut sources = Vec::with_capacity(cli.files.len());
    for path in &cli.files {
        let lines = read_lines(path)?;
        sources.push((path.clone(), lines));
    }

    let entries = parse_and_merge(&sources);

    let spike_config = RateSpikeConfig {
        bucket_ms: cli.bucket_ms,
        z_threshold: cli.z_threshold,
        min_count: cli.min_spike_count,
    };
    let cluster_config = ErrorClusterConfig {
        window_ms: cli.cluster_window_ms,
        rare_ratio: cli.rare_ratio,
        min_cluster_size: cli.min_cluster_size,
    };

    let spikes = detect_rate_spikes(&entries, &spike_config);
    let clusters = detect_rare_error_clusters(&entries, &cluster_config);

    match cli.format {
        Some(fmt_str) => {
            let format = OutputFormat::from_str(&fmt_str).map_err(anyhow::Error::msg)?;
            let index = AnomalyIndex::build(&spikes, cli.bucket_ms, &clusters);
            let records: Vec<_> = entries.iter().map(|e| annotate(e, &index)).collect();
            let stdout = io::stdout();
            let lock = stdout.lock();
            match format {
                OutputFormat::Json => write_json(lock, &records)?,
                OutputFormat::Csv => write_csv(lock, &records)?,
            }
        }
        None => {
            eprintln!(
                "logsculpt: {} entries, {} rate spikes, {} rare-error clusters — launching TUI (press q to quit)",
                entries.len(),
                spikes.len(),
                clusters.len()
            );
            let app = TuiApp::new(entries, &spikes, cli.bucket_ms, &clusters);
            run(app)?;
        }
    }

    Ok(())
}
