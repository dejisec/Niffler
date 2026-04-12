use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use bytesize::ByteSize;

use crate::classifier::Triage;

/// Thread-safe pipeline statistics with atomic counters.
/// Shared across pipeline phases via `Arc<PipelineStats>`.
#[derive(Debug)]
pub struct PipelineStats {
    pub hosts_scanned: AtomicU64,
    pub exports_found: AtomicU64,
    pub exports_failed: AtomicU64,
    pub exports_denied: AtomicU64,
    pub dirs_walked: AtomicU64,
    pub files_discovered: AtomicU64,
    pub files_content_scanned: AtomicU64,
    pub files_skipped_permission: AtomicU64,
    pub files_skipped_size: AtomicU64,
    pub files_skipped_binary: AtomicU64,
    pub findings: AtomicU64,
    pub findings_written: AtomicU64,
    pub findings_dropped: AtomicU64,
    pub errors_transient: AtomicU64,
    pub errors_stale: AtomicU64,
    pub errors_connection: AtomicU64,
    pub bytes_read: AtomicU64,
    pub scanner_retries: AtomicU64,
}

impl Default for PipelineStats {
    fn default() -> Self {
        Self {
            hosts_scanned: AtomicU64::new(0),
            exports_found: AtomicU64::new(0),
            exports_failed: AtomicU64::new(0),
            exports_denied: AtomicU64::new(0),
            dirs_walked: AtomicU64::new(0),
            files_discovered: AtomicU64::new(0),
            files_content_scanned: AtomicU64::new(0),
            files_skipped_permission: AtomicU64::new(0),
            files_skipped_size: AtomicU64::new(0),
            files_skipped_binary: AtomicU64::new(0),
            findings: AtomicU64::new(0),
            findings_written: AtomicU64::new(0),
            findings_dropped: AtomicU64::new(0),
            errors_transient: AtomicU64::new(0),
            errors_stale: AtomicU64::new(0),
            errors_connection: AtomicU64::new(0),
            bytes_read: AtomicU64::new(0),
            scanner_retries: AtomicU64::new(0),
        }
    }
}

impl PipelineStats {
    pub fn inc_hosts_scanned(&self) {
        self.hosts_scanned.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_exports_found(&self) {
        self.exports_found.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_exports_failed(&self) {
        self.exports_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_exports_denied(&self) {
        self.exports_denied.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_dirs_walked(&self) {
        self.dirs_walked.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_files_discovered(&self) {
        self.files_discovered.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_files_content_scanned(&self) {
        self.files_content_scanned.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_files_skipped_permission(&self) {
        self.files_skipped_permission
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_files_skipped_size(&self) {
        self.files_skipped_size.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_files_skipped_binary(&self) {
        self.files_skipped_binary.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_findings(&self) {
        self.findings.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_findings_written(&self, n: u64) {
        self.findings_written.fetch_add(n, Ordering::Relaxed);
    }

    pub fn inc_findings_dropped(&self) {
        self.findings_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_errors_transient(&self) {
        self.errors_transient.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_errors_stale(&self) {
        self.errors_stale.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_errors_connection(&self) {
        self.errors_connection.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_bytes_read(&self, n: u64) {
        self.bytes_read.fetch_add(n, Ordering::Relaxed);
    }

    pub fn inc_scanner_retries(&self) {
        self.scanner_retries.fetch_add(1, Ordering::Relaxed);
    }

    /// Create a point-in-time copy by reading all atomic counters.
    #[must_use]
    pub fn snapshot(&self) -> Self {
        Self {
            hosts_scanned: AtomicU64::new(self.hosts_scanned.load(Ordering::Relaxed)),
            exports_found: AtomicU64::new(self.exports_found.load(Ordering::Relaxed)),
            exports_failed: AtomicU64::new(self.exports_failed.load(Ordering::Relaxed)),
            exports_denied: AtomicU64::new(self.exports_denied.load(Ordering::Relaxed)),
            dirs_walked: AtomicU64::new(self.dirs_walked.load(Ordering::Relaxed)),
            files_discovered: AtomicU64::new(self.files_discovered.load(Ordering::Relaxed)),
            files_content_scanned: AtomicU64::new(
                self.files_content_scanned.load(Ordering::Relaxed),
            ),
            files_skipped_permission: AtomicU64::new(
                self.files_skipped_permission.load(Ordering::Relaxed),
            ),
            files_skipped_size: AtomicU64::new(self.files_skipped_size.load(Ordering::Relaxed)),
            files_skipped_binary: AtomicU64::new(self.files_skipped_binary.load(Ordering::Relaxed)),
            findings: AtomicU64::new(self.findings.load(Ordering::Relaxed)),
            findings_written: AtomicU64::new(self.findings_written.load(Ordering::Relaxed)),
            findings_dropped: AtomicU64::new(self.findings_dropped.load(Ordering::Relaxed)),
            errors_transient: AtomicU64::new(self.errors_transient.load(Ordering::Relaxed)),
            errors_stale: AtomicU64::new(self.errors_stale.load(Ordering::Relaxed)),
            errors_connection: AtomicU64::new(self.errors_connection.load(Ordering::Relaxed)),
            bytes_read: AtomicU64::new(self.bytes_read.load(Ordering::Relaxed)),
            scanner_retries: AtomicU64::new(self.scanner_retries.load(Ordering::Relaxed)),
        }
    }
}

/// Formats pipeline stats with severity-aware labels.
///
/// Progress bars show "Matches (all)" for total rule hits and
/// "Findings (>= {severity})" for the count that passed the
/// severity filter. This wrapper carries the `min_severity` from
/// config so `Display` can render the correct threshold.
pub struct StatsFormatter<'a> {
    pub stats: &'a PipelineStats,
    pub min_severity: Triage,
}

impl fmt::Display for StatsFormatter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.stats;
        let sev = self.min_severity;

        let hosts = s.hosts_scanned.load(Ordering::Relaxed);
        let exports = s.exports_found.load(Ordering::Relaxed);
        let exports_fail = s.exports_failed.load(Ordering::Relaxed);
        let exports_deny = s.exports_denied.load(Ordering::Relaxed);
        let dirs = s.dirs_walked.load(Ordering::Relaxed);
        let files_discovered = s.files_discovered.load(Ordering::Relaxed);
        let files_scanned = s.files_content_scanned.load(Ordering::Relaxed);
        let skip_perm = s.files_skipped_permission.load(Ordering::Relaxed);
        let skip_size = s.files_skipped_size.load(Ordering::Relaxed);
        let skip_binary = s.files_skipped_binary.load(Ordering::Relaxed);
        let findings = s.findings.load(Ordering::Relaxed);
        let findings_written = s.findings_written.load(Ordering::Relaxed);
        let err_transient = s.errors_transient.load(Ordering::Relaxed);
        let err_stale = s.errors_stale.load(Ordering::Relaxed);
        let err_conn = s.errors_connection.load(Ordering::Relaxed);
        let scan_retries = s.scanner_retries.load(Ordering::Relaxed);
        let bytes = s.bytes_read.load(Ordering::Relaxed);

        writeln!(f, "Scan Summary:")?;
        writeln!(f, "  Hosts scanned:              {hosts:>6}")?;
        writeln!(f, "  Exports found:              {exports:>6}")?;
        writeln!(f, "  Exports failed (fatal):     {exports_fail:>6}")?;
        writeln!(f, "  Exports denied (permission):{exports_deny:>6}")?;
        writeln!(f, "  Directories walked:         {dirs:>6}")?;
        writeln!(f, "  Files discovered:           {files_discovered:>6}")?;
        writeln!(f, "  Files content scanned:      {files_scanned:>6}")?;
        writeln!(f, "  Files skipped (permission): {skip_perm:>6}")?;
        writeln!(f, "  Files skipped (size):       {skip_size:>6}")?;
        writeln!(f, "  Files skipped (binary):     {skip_binary:>6}")?;
        writeln!(f, "  Matches (all):              {findings:>6}")?;
        writeln!(f, "  Findings (>= {sev}):{findings_written:>6}")?;
        writeln!(f, "  Errors (transient):         {err_transient:>6}")?;
        writeln!(f, "  Errors (stale handle):      {err_stale:>6}")?;
        writeln!(f, "  Errors (connection):        {err_conn:>6}")?;
        writeln!(f, "  Scanner retries:            {scan_retries:>6}")?;
        write!(f, "  Bytes read:            {}", ByteSize::b(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn stats_increment_individual_counters() {
        let stats = PipelineStats::default();

        stats.inc_hosts_scanned();
        assert_eq!(stats.hosts_scanned.load(Ordering::Relaxed), 1);
        stats.inc_hosts_scanned();
        assert_eq!(stats.hosts_scanned.load(Ordering::Relaxed), 2);

        stats.inc_findings();
        assert_eq!(stats.findings.load(Ordering::Relaxed), 1);

        stats.add_bytes_read(1024);
        assert_eq!(stats.bytes_read.load(Ordering::Relaxed), 1024);
    }

    #[tokio::test]
    async fn stats_concurrent_increment_from_multiple_tasks() {
        let stats = Arc::new(PipelineStats::default());
        let mut handles = Vec::new();

        for _ in 0..10 {
            let stats_clone = Arc::clone(&stats);
            handles.push(tokio::spawn(async move {
                for _ in 0..1000 {
                    stats_clone.inc_files_discovered();
                }
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        assert_eq!(stats.files_discovered.load(Ordering::Relaxed), 10_000);
    }

    #[test]
    fn stats_increment_export_failure_counters() {
        let stats = PipelineStats::default();

        stats.inc_exports_failed();
        assert_eq!(stats.exports_failed.load(Ordering::Relaxed), 1);
        stats.inc_exports_failed();
        assert_eq!(stats.exports_failed.load(Ordering::Relaxed), 2);

        stats.inc_exports_denied();
        assert_eq!(stats.exports_denied.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn stats_snapshot_copies_all_counters() {
        let stats = PipelineStats::default();
        stats.inc_hosts_scanned();
        stats.inc_hosts_scanned();
        stats.inc_findings();
        stats.inc_exports_failed();
        stats.inc_exports_denied();
        stats.add_bytes_read(1024);

        let snap = stats.snapshot();
        assert_eq!(snap.hosts_scanned.load(Ordering::Relaxed), 2);
        assert_eq!(snap.findings.load(Ordering::Relaxed), 1);
        assert_eq!(snap.bytes_read.load(Ordering::Relaxed), 1024);
        assert_eq!(snap.exports_found.load(Ordering::Relaxed), 0);
        assert_eq!(snap.exports_failed.load(Ordering::Relaxed), 1);
        assert_eq!(snap.exports_denied.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn stats_formatter_uses_severity_label() {
        use crate::classifier::Triage;

        let stats = PipelineStats::default();
        stats.inc_findings();
        stats.inc_findings();
        stats.add_findings_written(1);

        let fmt = StatsFormatter {
            stats: &stats,
            min_severity: Triage::Red,
        };
        let output = format!("{fmt}");

        assert!(
            output.contains("Matches (all):"),
            "should say 'Matches (all)': {output}"
        );
        assert!(
            output.contains("Findings (>= Red):"),
            "should say 'Findings (>= Red)': {output}"
        );
        // Must NOT contain old labels
        assert!(
            !output.contains("Findings written"),
            "old label should be gone: {output}"
        );
    }
}
