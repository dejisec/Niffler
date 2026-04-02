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
    Scan(ScanArgs),
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
    use crate::config::settings::ExportFormat;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("failed to parse CLI args")
    }

    fn parse_scan(args: &[&str]) -> ScanArgs {
        let cli = parse(args);
        match cli.command {
            NifflerCommand::Scan(args) => args,
            _ => panic!("expected Scan subcommand"),
        }
    }

    // ── Scan subcommand ────────────────────────────────────

    #[test]
    fn scan_subcommand_required() {
        let result = Cli::try_parse_from(["niffler"]);
        assert!(
            result.is_err(),
            "bare niffler with no subcommand should fail"
        );
    }

    #[test]
    fn scan_subcommand_parses() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1"]);
        assert!(args.targets.is_some());
    }

    // ── Serve subcommand ────────────────────────────────────

    #[test]
    fn serve_subcommand_parses() {
        let cli = parse(&["niffler", "serve", "--db", "scan.db"]);
        match cli.command {
            NifflerCommand::Serve { ref db, .. } => {
                assert_eq!(db, &PathBuf::from("scan.db"));
            }
            _ => panic!("expected Serve"),
        }
    }

    #[test]
    fn serve_default_port() {
        let cli = parse(&["niffler", "serve", "--db", "scan.db"]);
        match cli.command {
            NifflerCommand::Serve { port, .. } => assert_eq!(port, 8080),
            _ => panic!("expected Serve"),
        }
    }

    #[test]
    fn serve_custom_port() {
        let cli = parse(&["niffler", "serve", "--db", "scan.db", "--port", "9090"]);
        match cli.command {
            NifflerCommand::Serve { port, .. } => assert_eq!(port, 9090),
            _ => panic!("expected Serve"),
        }
    }

    #[test]
    fn serve_default_bind() {
        let cli = parse(&["niffler", "serve", "--db", "scan.db"]);
        match cli.command {
            NifflerCommand::Serve { ref bind, .. } => {
                assert_eq!(bind, "127.0.0.1");
            }
            _ => panic!("expected Serve"),
        }
    }

    #[test]
    fn serve_requires_db() {
        let result = Cli::try_parse_from(["niffler", "serve"]);
        assert!(result.is_err(), "serve without --db should fail");
    }

    // ── Export subcommand ───────────────────────────────────

    #[test]
    fn export_subcommand_parses() {
        let cli = parse(&["niffler", "export", "--db", "scan.db", "-f", "json"]);
        match cli.command {
            NifflerCommand::Export { ref db, format, .. } => {
                assert_eq!(db, &PathBuf::from("scan.db"));
                assert_eq!(format, ExportFormat::Json);
            }
            _ => panic!("expected Export"),
        }
    }

    #[test]
    fn export_requires_db() {
        let result = Cli::try_parse_from(["niffler", "export", "-f", "json"]);
        assert!(result.is_err(), "export without --db should fail");
    }

    #[test]
    fn export_requires_format() {
        let result = Cli::try_parse_from(["niffler", "export", "--db", "scan.db"]);
        assert!(result.is_err(), "export without -f should fail");
    }

    #[test]
    fn export_all_formats() {
        for fmt in ["json", "csv", "tsv"] {
            let cli = parse(&["niffler", "export", "--db", "scan.db", "-f", fmt]);
            assert!(
                matches!(cli.command, NifflerCommand::Export { .. }),
                "format '{fmt}' should parse"
            );
        }
    }

    #[test]
    fn export_optional_severity_filter() {
        let cli = parse(&[
            "niffler", "export", "--db", "scan.db", "-f", "json", "-b", "red",
        ]);
        match cli.command {
            NifflerCommand::Export { min_severity, .. } => {
                assert_eq!(min_severity, Some(Triage::Red));
            }
            _ => panic!("expected Export"),
        }
    }

    #[test]
    fn export_optional_host_filter() {
        let cli = parse(&[
            "niffler", "export", "--db", "scan.db", "-f", "json", "--host", "10.0.1.5",
        ]);
        match cli.command {
            NifflerCommand::Export { ref host, .. } => {
                assert_eq!(host, &Some("10.0.1.5".into()));
            }
            _ => panic!("expected Export"),
        }
    }

    #[test]
    fn export_optional_scan_id() {
        let cli = parse(&[
            "niffler",
            "export",
            "--db",
            "scan.db",
            "-f",
            "json",
            "--scan-id",
            "3",
        ]);
        match cli.command {
            NifflerCommand::Export { scan_id, .. } => {
                assert_eq!(scan_id, Some(3));
            }
            _ => panic!("expected Export"),
        }
    }

    // ── Scan defaults ──────────────────────────────────────

    #[test]
    fn cli_default_mode_is_scan() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1"]);
        assert_eq!(args.mode, OperatingMode::Scan);
    }

    #[test]
    fn cli_default_db_path() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1"]);
        assert_eq!(args.output, PathBuf::from("niffler.db"));
    }

    #[test]
    fn cli_custom_db_path() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1", "-o", "custom.db"]);
        assert_eq!(args.output, PathBuf::from("custom.db"));
    }

    #[test]
    fn cli_live_flag() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1", "--live"]);
        assert!(args.live);
    }

    #[test]
    fn cli_live_short_flag() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1", "-l"]);
        assert!(args.live);
    }

    #[test]
    fn cli_default_live_is_false() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1"]);
        assert!(!args.live);
    }

    #[test]
    fn cli_default_min_severity_is_green() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1"]);
        assert_eq!(args.min_severity, Triage::Green);
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
    fn cli_mode_flag_override() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1", "-m", "recon"]);
        assert_eq!(args.mode, OperatingMode::Recon);
    }

    #[test]
    fn cli_targets_multiple() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1", "10.0.0.2"]);
        let targets = args.targets.expect("targets should be Some");
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn cli_local_path_multiple() {
        let args = parse_scan(&["niffler", "scan", "-i", "/tmp/a", "/tmp/b"]);
        let paths = args.local_path.expect("local_path should be Some");
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn cli_output_path() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1", "-o", "/tmp/results.db"]);
        assert_eq!(args.output, PathBuf::from("/tmp/results.db"));
    }

    // ── Global verbosity ───────────────────────────────────

    #[test]
    fn verbosity_global_before_subcommand() {
        let cli = parse(&["niffler", "-v", "debug", "scan", "-t", "10.0.0.1"]);
        assert!(matches!(cli.verbosity, Verbosity::Debug));
    }

    #[test]
    fn verbosity_global_after_subcommand() {
        let cli = parse(&["niffler", "scan", "-t", "10.0.0.1", "-v", "debug"]);
        assert!(matches!(cli.verbosity, Verbosity::Debug));
    }
}
