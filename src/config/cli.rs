use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::classifier::Triage;
use crate::config::settings::{ExportFormat, OperatingMode};

#[derive(Parser)]
#[command(name = "niffler", about = "NFS share secret finder")]
pub struct Cli {
    #[command(subcommand)]
    pub command: NifflerCommand,

    /// Log verbosity level
    #[arg(short = 'v', long, default_value = "info", global = true)]
    pub verbosity: Verbosity,
}

#[derive(Subcommand, Debug)]
pub enum NifflerCommand {
    /// Scan NFS shares for secrets
    Scan(Box<ScanArgs>),
    /// Launch web dashboard for interactive triage
    Serve {
        /// Path to SQLite database
        #[arg(long)]
        db: PathBuf,

        /// Port to listen on
        #[arg(long, default_value = "8080")]
        port: u16,

        /// Address to bind to
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
    },
    /// Export findings from database to stdout
    Export {
        /// Path to SQLite database
        #[arg(long)]
        db: PathBuf,

        /// Output format
        #[arg(short = 'f', long)]
        format: ExportFormat,

        /// Minimum triage severity to include
        #[arg(short = 'b', long)]
        min_severity: Option<Triage>,

        /// Filter by host
        #[arg(long)]
        host: Option<String>,

        /// Filter by rule name
        #[arg(long)]
        rule: Option<String>,

        /// Filter by scan ID
        #[arg(long)]
        scan_id: Option<i64>,
    },
}

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Targets: IP addresses, hostnames, or CIDR ranges
    #[arg(short = 't', long, num_args = 1..)]
    pub targets: Option<Vec<String>>,

    /// Read targets from file (one per line), use '-' for stdin
    #[arg(short = 'T', long = "target-file")]
    pub target_file: Option<String>,

    /// Scan local/mounted paths instead of discovering NFS shares
    #[arg(short = 'i', long, num_args = 1..)]
    pub local_path: Option<Vec<PathBuf>>,

    /// Operating mode
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

    /// Database output path
    #[arg(short = 'o', long, default_value = "niffler.db")]
    pub output: PathBuf,

    /// Print findings to terminal alongside database write
    #[arg(short = 'l', long)]
    pub live: bool,

    /// UID for NFS AUTH_SYS credentials
    #[arg(long, default_value = "65534")]
    pub uid: u32,

    /// GID for NFS AUTH_SYS credentials
    #[arg(long, default_value = "65534")]
    pub gid: u32,

    /// Auto-cycle through discovered UIDs on permission denied
    #[arg(long, default_value_t = true)]
    pub uid_cycle: bool,

    /// Max UID attempts per file before giving up
    #[arg(long, default_value = "5")]
    pub max_uid_attempts: usize,

    /// Force NFS version (auto-detect if not set)
    #[arg(long)]
    pub nfs_version: Option<u8>,

    /// Bind source port < 1024
    #[arg(long, default_value_t = true)]
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

    /// Max retries per export walk on connection loss (0 = no retry)
    #[arg(long, default_value = "2")]
    pub walk_retries: usize,

    /// Base delay in ms between walk retries (linearly scaled: attempt * delay)
    #[arg(long, default_value = "500")]
    pub walk_retry_delay: u64,

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

    fn parse_scan(args: &[&str]) -> ScanArgs {
        let cli = parse(args);
        match cli.command {
            NifflerCommand::Scan(args) => *args,
            _ => panic!("expected Scan subcommand"),
        }
    }

    #[test]
    fn scan_subcommand_required() {
        let result = Cli::try_parse_from(["niffler"]);
        assert!(
            result.is_err(),
            "bare niffler with no subcommand should fail"
        );
    }

    #[test]
    fn cli_default_numeric_values() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1"]);
        assert_eq!(
            args.uid, 65534,
            "default UID should be nobody (65534) for predictable baseline access"
        );
        assert_eq!(
            args.gid, 65534,
            "default GID should be nobody (65534) to match default UID"
        );
        assert_eq!(args.max_depth, 50);
        assert_eq!(args.max_scan_size, 1_048_576);
        assert_eq!(args.discovery_tasks, 30);
        assert_eq!(args.walker_tasks, 20);
        assert_eq!(args.scanner_tasks, 50);
        assert_eq!(args.max_connections_per_host, 8);
        assert_eq!(args.max_uid_attempts, 5);
    }

    #[test]
    fn cli_default_bool_flags() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1"]);
        assert!(args.uid_cycle);
        assert!(args.privileged_port);
        assert!(!args.generate_config);
        assert!(!args.check_subtree_bypass);
        assert!(!args.live);
    }

    #[test]
    fn verbosity_global_after_subcommand() {
        let cli = parse(&["niffler", "scan", "-t", "10.0.0.1", "-v", "debug"]);
        assert!(matches!(cli.verbosity, Verbosity::Debug));
    }
}
