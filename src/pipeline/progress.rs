use std::io;
use std::sync::atomic::Ordering::Relaxed;

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use tracing_subscriber::fmt::MakeWriter;

use crate::classifier::Triage;

use super::PipelineStats;

/// Factory that produces line-buffered writers routing tracing output through
/// `MultiProgress::println()`, so log lines don't get clobbered by progress bars.
#[derive(Clone)]
pub struct IndicatifWriter {
    multi: MultiProgress,
}

impl IndicatifWriter {
    #[must_use]
    pub fn new(multi: MultiProgress) -> Self {
        Self { multi }
    }
}

impl<'a> MakeWriter<'a> for IndicatifWriter {
    type Writer = IndicatifLineWriter;

    fn make_writer(&'a self) -> Self::Writer {
        IndicatifLineWriter {
            multi: self.multi.clone(),
            buf: Vec::with_capacity(256),
        }
    }
}

/// Per-event writer that buffers a log line and flushes via
/// `MultiProgress::println` on drop.
pub struct IndicatifLineWriter {
    multi: MultiProgress,
    buf: Vec<u8>,
}

impl io::Write for IndicatifLineWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for IndicatifLineWriter {
    fn drop(&mut self) {
        if !self.buf.is_empty() {
            let s = String::from_utf8_lossy(&self.buf);
            let trimmed = s.trim_end();
            if !trimmed.is_empty() {
                let _ = self.multi.println(trimmed);
            }
        }
    }
}

pub struct ProgressDisplay {
    discovery_bar: Option<ProgressBar>,
    walker_bar: Option<ProgressBar>,
    scanner_bar: Option<ProgressBar>,
    findings_bar: Option<ProgressBar>,
    output_bar: Option<ProgressBar>,
}

impl ProgressDisplay {
    /// Create a new progress display. Pass `Some(multi)` to enable progress bars,
    /// `None` to disable them (e.g. when writing to a file or non-console format).
    #[must_use]
    pub fn new(multi: Option<MultiProgress>, min_severity: Triage) -> Self {
        let Some(multi) = multi else {
            return Self {
                discovery_bar: None,
                walker_bar: None,
                scanner_bar: None,
                findings_bar: None,
                output_bar: None,
            };
        };

        let spinner = ProgressStyle::with_template("{spinner:.green} {msg}: {pos}")
            .expect("valid progress template");

        let discovery_bar = multi.add(ProgressBar::new_spinner());
        discovery_bar.set_style(spinner.clone());
        discovery_bar.set_message("Discovery (hosts scanned)");

        let walker_bar = multi.add(ProgressBar::new_spinner());
        walker_bar.set_style(spinner.clone());
        walker_bar.set_message("Walking (dirs)");

        let scanner_bar = multi.add(ProgressBar::new_spinner());
        scanner_bar.set_style(spinner.clone());
        scanner_bar.set_message("Scanning (files)");

        let findings_bar = multi.add(ProgressBar::new_spinner());
        findings_bar.set_style(spinner.clone());
        findings_bar.set_message("Matches (all)".to_string());

        let output_bar = multi.add(ProgressBar::new_spinner());
        output_bar.set_style(spinner);
        output_bar.set_message(format!("Findings (>= {min_severity})"));

        Self {
            discovery_bar: Some(discovery_bar),
            walker_bar: Some(walker_bar),
            scanner_bar: Some(scanner_bar),
            findings_bar: Some(findings_bar),
            output_bar: Some(output_bar),
        }
    }

    pub fn update_from_stats(&self, stats: &PipelineStats) {
        if let Some(ref bar) = self.discovery_bar {
            bar.set_position(stats.hosts_scanned.load(Relaxed));
        }
        if let Some(ref bar) = self.walker_bar {
            bar.set_position(stats.dirs_walked.load(Relaxed));
        }
        if let Some(ref bar) = self.scanner_bar {
            bar.set_position(stats.files_content_scanned.load(Relaxed));
        }
        if let Some(ref bar) = self.findings_bar {
            bar.set_position(stats.findings.load(Relaxed));
        }
        if let Some(ref bar) = self.output_bar {
            bar.set_position(stats.findings_written.load(Relaxed));
        }
    }

    pub fn finish(&self) {
        if let Some(ref bar) = self.discovery_bar {
            bar.finish_with_message("Discovery (done)");
        }
        if let Some(ref bar) = self.walker_bar {
            bar.finish_with_message("Walking (done)");
        }
        if let Some(ref bar) = self.scanner_bar {
            bar.finish_with_message("Scanning (done)");
        }
        if let Some(ref bar) = self.findings_bar {
            bar.finish_with_message("Matches (done)");
        }
        if let Some(ref bar) = self.output_bar {
            bar.finish_with_message("Findings (done)");
        }
    }
}
