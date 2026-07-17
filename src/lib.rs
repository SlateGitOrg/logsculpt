//! logsculpt: a streaming log parser, normalizer, and anomaly-detecting
//! timeline for incident response. See README.md for the full pitch.

pub mod anomaly;
pub mod ingest;
pub mod output;
pub mod parsers;
pub mod schema;
pub mod time_util;
pub mod tui;
