use std::path::PathBuf;

use clap::Parser;
use clap::ValueEnum;

use crate::classifier::Triage;
use crate::config::settings::{OperatingMode, OutputFormat};

#[derive(Parser)]
#[command(name = "niffler", about = "NFS share secret finder")]
pub struct Cli {
    /// Targets: IP addresses, hostnames, or CIDR ranges
    #[arg(short = 't', long, num_args = 1..)]
    pub targets: Option<Vec<String>>,

    /// Read targets from file (one per line), use '-' for stdin
    #[arg(short = 'T', long = "target-file")]
    pub target_file: Option<String>,

    /// Scan local/mounted paths instead of discovering NFS shares
    #[arg(short = 'i', long, num_args = 1..)]
    pub local_path: Option<Vec<PathBuf>>,

    /// Operating mode: recon (discovery only), enum (no content scan), scan (full)
    #[arg(short = 'm', long, default_value = "scan")]
    pub mode: OperatingMode,

    /// Path to custom rules directory (replaces defaults)
    #[arg(short = 'r', long)]
    pub rules_dir: Option<PathBuf>,

    /// Path to additional rules (merged with defaults)
    #[arg(short = 'R', long)]
    pub extra_rules: Option<PathBuf>,

    /// Minimum triage severity to report
    #[arg(short = 'b', long, default_value = "green")]
    pub min_severity: Triage,

    /// Output format: console, json, tsv
    #[arg(short = 'f', long, default_value = "console")]
    pub format: OutputFormat,

    /// Output file path (stdout if not set)
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    /// UID for NFS AUTH_SYS credentials (nobody=65534 avoids root_squash)
    #[arg(long, default_value = "65534")]
    pub uid: u32,

    /// GID for NFS AUTH_SYS credentials (nobody=65534 avoids root_squash)
    #[arg(long, default_value = "65534")]
    pub gid: u32,

    /// Auto-cycle through discovered UIDs on permission denied
    #[arg(long, default_value = "true")]
    pub uid_cycle: bool,

    /// Max UID attempts per file before giving up
    #[arg(long, default_value = "5")]
    pub max_uid_attempts: usize,

    /// Force NFS version (auto-detect if not set)
    #[arg(long)]
    pub nfs_version: Option<u8>,

    /// Bind source port < 1024 (for servers with nfs_portmon)
    #[arg(long)]
    pub privileged_port: bool,

    /// SOCKS5 proxy for all connections (e.g., socks5://127.0.0.1:1080)
    #[arg(long)]
    pub proxy: Option<String>,

    /// Max concurrent NFS connections per host
    #[arg(long, default_value = "8")]
    pub max_connections_per_host: usize,

    /// Max concurrent discovery tasks
    #[arg(long, default_value = "30")]
    pub discovery_tasks: usize,

    /// Timeout in seconds for discovery network operations (portmapper, mount)
    #[arg(long, default_value = "5")]
    pub discovery_timeout: u64,

    /// Max concurrent tree walk tasks (one per export)
    #[arg(long, default_value = "20")]
    pub walker_tasks: usize,

    /// Max concurrent file scan tasks
    #[arg(long, default_value = "50")]
    pub scanner_tasks: usize,

    /// Max directory depth during tree walk
    #[arg(long, default_value = "50")]
    pub max_depth: usize,

    /// Max file size to read content from (bytes)
    #[arg(long, default_value = "1048576")]
    pub max_scan_size: u64,

    /// Attempt subtree_check bypass detection via filehandle manipulation
    #[arg(long)]
    pub check_subtree_bypass: bool,

    /// Serialize current config to TOML and exit
    #[arg(short = 'z', long)]
    pub generate_config: bool,

    /// Load config from file (overrides CLI defaults, CLI flags override config)
    #[arg(short = 'c', long)]
    pub config: Option<PathBuf>,

    /// Verbosity: trace, debug, info, warn, error
    #[arg(short = 'v', long, default_value = "info")]
    pub verbosity: Verbosity,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Verbosity {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("failed to parse CLI args")
    }

    #[test]
    fn cli_default_mode_is_scan() {
        let cli = parse(&["niffler", "-t", "10.0.0.1"]);
        assert_eq!(cli.mode, OperatingMode::Scan);
    }

    #[test]
    fn cli_default_format_is_console() {
        let cli = parse(&["niffler", "-t", "10.0.0.1"]);
        assert_eq!(cli.format, OutputFormat::Console);
    }

    #[test]
    fn cli_default_min_severity_is_green() {
        let cli = parse(&["niffler", "-t", "10.0.0.1"]);
        assert_eq!(cli.min_severity, Triage::Green);
    }

    #[test]
    fn cli_default_numeric_values() {
        let cli = parse(&["niffler", "-t", "10.0.0.1"]);
        assert_eq!(
            cli.uid, 65534,
            "default UID should be nobody to avoid root_squash"
        );
        assert_eq!(
            cli.gid, 65534,
            "default GID should be nobody to avoid root_squash"
        );
        assert_eq!(cli.max_depth, 50);
        assert_eq!(cli.max_scan_size, 1_048_576);
        assert_eq!(cli.discovery_tasks, 30);
        assert_eq!(cli.walker_tasks, 20);
        assert_eq!(cli.scanner_tasks, 50);
        assert_eq!(cli.max_connections_per_host, 8);
        assert_eq!(cli.max_uid_attempts, 5);
    }

    #[test]
    fn cli_default_bool_flags() {
        let cli = parse(&["niffler", "-t", "10.0.0.1"]);
        assert!(cli.uid_cycle);
        assert!(!cli.privileged_port);
        assert!(!cli.generate_config);
        assert!(!cli.check_subtree_bypass);
    }

    #[test]
    fn cli_mode_flag_override() {
        let cli = parse(&["niffler", "-t", "10.0.0.1", "-m", "recon"]);
        assert_eq!(cli.mode, OperatingMode::Recon);
    }

    #[test]
    fn cli_format_flag_override() {
        let cli = parse(&["niffler", "-t", "10.0.0.1", "-f", "json"]);
        assert_eq!(cli.format, OutputFormat::Json);
    }

    #[test]
    fn cli_targets_multiple() {
        let cli = parse(&["niffler", "-t", "10.0.0.1", "10.0.0.2"]);
        let targets = cli.targets.expect("targets should be Some");
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn cli_local_path_multiple() {
        let cli = parse(&["niffler", "-i", "/tmp/a", "/tmp/b"]);
        let paths = cli.local_path.expect("local_path should be Some");
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn cli_output_file() {
        let cli = parse(&["niffler", "-t", "10.0.0.1", "-o", "/tmp/out.json"]);
        assert_eq!(
            cli.output.expect("output should be Some"),
            PathBuf::from("/tmp/out.json")
        );
    }
}
