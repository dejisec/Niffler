use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::classifier::Triage;
use crate::config::cli::ScanArgs;

/// Export output format — used by the `export` subcommand and web export handlers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Json,
    Csv,
    Tsv,
}

impl fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json => write!(f, "json"),
            Self::Csv => write!(f, "csv"),
            Self::Tsv => write!(f, "tsv"),
        }
    }
}

/// Controls which pipeline phases execute.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperatingMode {
    /// Discovery only — enumerate exports and report misconfigurations.
    Recon,
    /// Discovery + tree walk + filename rules — no content reads.
    #[value(alias = "enum")]
    Enumerate,
    /// Full pipeline — discovery, walk, and content scanning.
    #[default]
    Scan,
}

impl fmt::Display for OperatingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Recon => write!(f, "recon"),
            Self::Enumerate => write!(f, "enumerate"),
            Self::Scan => write!(f, "scan"),
        }
    }
}

impl OperatingMode {
    /// Returns `true` if this mode spawns the tree walker phase.
    pub fn runs_walker(&self) -> bool {
        matches!(self, Self::Enumerate | Self::Scan)
    }

    /// Returns `true` if this mode reads file content for scanning.
    pub fn runs_content_scan(&self) -> bool {
        matches!(self, Self::Scan)
    }
}

/// Discovery phase settings — target resolution, port scanning, export listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    pub targets: Option<Vec<String>>,
    pub target_file: Option<String>,
    pub nfs_version: Option<u8>,
    pub privileged_port: bool,
    pub discovery_tasks: usize,
    pub timeout_secs: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<SocketAddr>,
}

/// Tree walker settings — recursive directory traversal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalkerConfig {
    pub walker_tasks: usize,
    pub max_depth: usize,
    pub local_paths: Option<Vec<PathBuf>>,
    pub max_connections_per_host: usize,
}

/// File scanner settings — content reading, UID cycling, connection limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    pub scanner_tasks: usize,
    pub max_scan_size: u64,
    pub uid: u32,
    pub gid: u32,
    pub uid_cycle: bool,
    pub max_uid_attempts: usize,
    pub max_connections_per_host: usize,
    pub check_subtree_bypass: bool,
}

/// Output settings — SQLite database path and optional live console tee.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub db_path: PathBuf,
    pub live: bool,
    pub min_severity: Triage,
}

/// Merged configuration consumed by `run_pipeline()` and all downstream phases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NifflerConfig {
    pub mode: OperatingMode,
    pub discovery: DiscoveryConfig,
    pub walker: WalkerConfig,
    pub scanner: ScannerConfig,
    pub output: OutputConfig,
    pub rules_dir: Option<PathBuf>,
    pub extra_rules: Option<PathBuf>,
    pub min_severity: Triage,
    pub generate_config: bool,
}

impl NifflerConfig {
    /// Build a `NifflerConfig` from parsed scan subcommand arguments.
    ///
    /// Validates that at least one target source is provided unless `-z` is set.
    pub fn from_scan_args(args: ScanArgs) -> Result<Self> {
        if args.targets.is_none()
            && args.target_file.is_none()
            && args.local_path.is_none()
            && !args.generate_config
        {
            bail!(
                "no targets specified: provide -t <targets>, -T <file>, -i <path>, or -z to generate config"
            );
        }

        let proxy = args.proxy.as_deref().map(parse_proxy_url).transpose()?;

        Ok(Self {
            mode: args.mode,
            discovery: DiscoveryConfig {
                targets: args.targets,
                target_file: args.target_file,
                nfs_version: args.nfs_version,
                privileged_port: args.privileged_port,
                discovery_tasks: args.discovery_tasks,
                timeout_secs: args.discovery_timeout,
                proxy,
            },
            walker: WalkerConfig {
                walker_tasks: args.walker_tasks,
                max_depth: args.max_depth,
                local_paths: args.local_path,
                max_connections_per_host: args.max_connections_per_host,
            },
            scanner: ScannerConfig {
                scanner_tasks: args.scanner_tasks,
                max_scan_size: args.max_scan_size,
                uid: args.uid,
                gid: args.gid,
                uid_cycle: args.uid_cycle,
                max_uid_attempts: args.max_uid_attempts,
                max_connections_per_host: args.max_connections_per_host,
                check_subtree_bypass: args.check_subtree_bypass,
            },
            output: OutputConfig {
                db_path: args.output,
                live: args.live,
                min_severity: args.min_severity,
            },
            rules_dir: args.rules_dir,
            extra_rules: args.extra_rules,
            min_severity: args.min_severity,
            generate_config: args.generate_config,
        })
    }
}

/// Parse a proxy URL like `socks5://host:port` or `host:port` into a `SocketAddr`.
fn parse_proxy_url(url: &str) -> Result<SocketAddr> {
    let addr_str = url
        .strip_prefix("socks5://")
        .or_else(|| url.strip_prefix("socks://"))
        .unwrap_or(url);
    addr_str
        .parse::<SocketAddr>()
        .map_err(|e| anyhow::anyhow!("invalid proxy address '{}': {}", addr_str, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::cli::{Cli, NifflerCommand};
    use clap::Parser;

    fn parse_scan(args: &[&str]) -> ScanArgs {
        let cli = Cli::try_parse_from(args).expect("failed to parse CLI args");
        match cli.command {
            NifflerCommand::Scan(args) => args,
            _ => panic!("expected Scan subcommand"),
        }
    }

    #[test]
    fn recon_does_not_run_walker() {
        assert!(!OperatingMode::Recon.runs_walker());
    }

    #[test]
    fn recon_does_not_run_content_scan() {
        assert!(!OperatingMode::Recon.runs_content_scan());
    }

    #[test]
    fn enumerate_runs_walker() {
        assert!(OperatingMode::Enumerate.runs_walker());
    }

    #[test]
    fn enumerate_does_not_run_content_scan() {
        assert!(!OperatingMode::Enumerate.runs_content_scan());
    }

    #[test]
    fn scan_runs_walker_and_content() {
        assert!(OperatingMode::Scan.runs_walker());
        assert!(OperatingMode::Scan.runs_content_scan());
    }

    #[test]
    fn operating_mode_default_is_scan() {
        assert_eq!(OperatingMode::default(), OperatingMode::Scan);
    }

    #[test]
    fn operating_mode_display() {
        assert_eq!(OperatingMode::Recon.to_string(), "recon");
        assert_eq!(OperatingMode::Enumerate.to_string(), "enumerate");
        assert_eq!(OperatingMode::Scan.to_string(), "scan");
    }

    #[test]
    fn output_config_has_db_path() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1"]);
        let config = NifflerConfig::from_scan_args(args).unwrap();
        assert_eq!(config.output.db_path, PathBuf::from("niffler.db"));
    }

    #[test]
    fn output_config_has_live_flag() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1"]);
        let config = NifflerConfig::from_scan_args(args).unwrap();
        assert!(!config.output.live);
    }

    #[test]
    fn config_from_scan_args_with_defaults() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1"]);
        let config = NifflerConfig::from_scan_args(args).unwrap();
        assert_eq!(config.mode, OperatingMode::Scan);
        assert_eq!(config.output.db_path, PathBuf::from("niffler.db"));
        assert!(!config.output.live);
        assert_eq!(config.scanner.max_scan_size, 1_048_576);
        assert_eq!(config.discovery.discovery_tasks, 30);
        assert_eq!(config.walker.walker_tasks, 20);
        assert_eq!(config.scanner.scanner_tasks, 50);
        assert_eq!(config.min_severity, Triage::Green);
    }

    #[test]
    fn config_from_scan_args_maps_discovery() {
        let args = parse_scan(&[
            "niffler",
            "scan",
            "-t",
            "10.0.0.1",
            "192.168.1.0/24",
            "--nfs-version",
            "3",
            "--privileged-port",
        ]);
        let config = NifflerConfig::from_scan_args(args).unwrap();
        let targets = config.discovery.targets.unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0], "10.0.0.1");
        assert_eq!(targets[1], "192.168.1.0/24");
        assert_eq!(config.discovery.nfs_version, Some(3));
        assert!(config.discovery.privileged_port);
    }

    #[test]
    fn config_from_scan_args_maps_scanner() {
        let args = parse_scan(&[
            "niffler",
            "scan",
            "-t",
            "10.0.0.1",
            "--uid",
            "1000",
            "--gid",
            "1000",
            "--max-scan-size",
            "2097152",
            "--max-uid-attempts",
            "10",
        ]);
        let config = NifflerConfig::from_scan_args(args).unwrap();
        assert_eq!(config.scanner.uid, 1000);
        assert_eq!(config.scanner.gid, 1000);
        assert_eq!(config.scanner.max_scan_size, 2_097_152);
        assert!(config.scanner.uid_cycle);
        assert_eq!(config.scanner.max_uid_attempts, 10);
    }

    #[test]
    fn config_from_scan_args_maps_output() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1", "-o", "/tmp/results.db"]);
        let config = NifflerConfig::from_scan_args(args).unwrap();
        assert_eq!(config.output.db_path, PathBuf::from("/tmp/results.db"));
    }

    #[test]
    fn config_from_scan_args_maps_live_flag() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1", "--live"]);
        let config = NifflerConfig::from_scan_args(args).unwrap();
        assert!(config.output.live);
    }

    #[test]
    fn config_from_scan_args_no_targets_error() {
        let args = parse_scan(&["niffler", "scan"]);
        let result = NifflerConfig::from_scan_args(args);
        assert!(result.is_err());
    }

    #[test]
    fn config_from_scan_args_local_path_no_targets_ok() {
        let args = parse_scan(&["niffler", "scan", "-i", "/mnt/share"]);
        let result = NifflerConfig::from_scan_args(args);
        assert!(result.is_ok());
    }

    #[test]
    fn config_from_scan_args_generate_config_no_targets_ok() {
        let args = parse_scan(&["niffler", "scan", "-z"]);
        let result = NifflerConfig::from_scan_args(args);
        assert!(result.is_ok());
    }

    #[test]
    fn config_toml_round_trip() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1", "--live"]);
        let config = NifflerConfig::from_scan_args(args).unwrap();
        let toml_str = toml::to_string_pretty(&config).expect("serialize to TOML");
        let restored: NifflerConfig = toml::from_str(&toml_str).expect("deserialize from TOML");
        assert_eq!(restored.mode, config.mode);
        assert_eq!(restored.output.db_path, config.output.db_path);
        assert_eq!(restored.output.live, config.output.live);
        assert_eq!(restored.scanner.max_scan_size, config.scanner.max_scan_size);
        assert_eq!(restored.min_severity, config.min_severity);
    }

    #[test]
    fn config_serializes_to_valid_toml() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1"]);
        let config = NifflerConfig::from_scan_args(args).unwrap();
        let toml_str = toml::to_string_pretty(&config).expect("serialize");
        let value: toml::Value = toml::from_str(&toml_str).expect("parse as TOML Value");
        assert!(value.is_table());
    }

    #[test]
    fn config_serialization_contains_all_sections() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1"]);
        let config = NifflerConfig::from_scan_args(args).unwrap();
        let toml_str = toml::to_string_pretty(&config).expect("serialize");
        let value: toml::Value = toml::from_str(&toml_str).unwrap();
        let table = value.as_table().unwrap();
        for section in ["discovery", "walker", "scanner", "output"] {
            assert!(table.contains_key(section), "missing section: [{section}]");
            assert!(table[section].is_table(), "[{section}] should be a table");
        }
    }

    #[test]
    fn config_serialization_contains_key_fields() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1"]);
        let config = NifflerConfig::from_scan_args(args).unwrap();
        let toml_str = toml::to_string_pretty(&config).expect("serialize");
        let value: toml::Value = toml::from_str(&toml_str).unwrap();
        let table = value.as_table().unwrap();

        // Top-level fields
        assert!(table.contains_key("mode"), "missing: mode");
        assert!(table.contains_key("min_severity"), "missing: min_severity");

        // Nested fields
        let discovery = table["discovery"].as_table().unwrap();
        assert!(
            discovery.contains_key("discovery_tasks"),
            "missing: discovery_tasks"
        );

        let walker = table["walker"].as_table().unwrap();
        assert!(walker.contains_key("max_depth"), "missing: max_depth");
        assert!(walker.contains_key("walker_tasks"), "missing: walker_tasks");

        let scanner = table["scanner"].as_table().unwrap();
        for field in ["max_scan_size", "uid", "gid", "uid_cycle", "scanner_tasks"] {
            assert!(scanner.contains_key(field), "missing: {field}");
        }

        let output = table["output"].as_table().unwrap();
        assert!(output.contains_key("db_path"), "missing: db_path");
        assert!(output.contains_key("live"), "missing: live");
    }

    #[test]
    fn config_serialization_enums_as_strings() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1"]);
        let config = NifflerConfig::from_scan_args(args).unwrap();
        let toml_str = toml::to_string_pretty(&config).expect("serialize");
        let value: toml::Value = toml::from_str(&toml_str).unwrap();
        let table = value.as_table().unwrap();

        // OperatingMode serializes as lowercase string
        let mode = &table["mode"];
        assert_eq!(mode.as_str().unwrap(), "scan");
        assert!(mode.as_integer().is_none(), "mode should not be an integer");

        // Triage serializes as PascalCase string (no rename_all)
        let severity = &table["min_severity"];
        assert_eq!(severity.as_str().unwrap(), "Green");
        assert!(
            severity.as_integer().is_none(),
            "min_severity should not be an integer"
        );
    }

    #[test]
    fn config_round_trip_preserves_non_default_values() {
        let args = parse_scan(&[
            "niffler",
            "scan",
            "-t",
            "10.0.0.1",
            "-m",
            "recon",
            "--live",
            "-b",
            "red",
            "--uid",
            "1000",
            "--gid",
            "2000",
            "--max-depth",
            "10",
            "--max-scan-size",
            "524288",
            "--scanner-tasks",
            "25",
            "--walker-tasks",
            "5",
            "--discovery-tasks",
            "15",
        ]);
        let config = NifflerConfig::from_scan_args(args).unwrap();
        let toml_str = toml::to_string_pretty(&config).expect("serialize");
        let restored: NifflerConfig = toml::from_str(&toml_str).expect("deserialize");

        assert_eq!(restored.mode, OperatingMode::Recon);
        assert!(restored.output.live);
        assert_eq!(restored.min_severity, Triage::Red);
        assert_eq!(restored.scanner.uid, 1000);
        assert_eq!(restored.scanner.gid, 2000);
        assert_eq!(restored.walker.max_depth, 10);
        assert_eq!(restored.scanner.max_scan_size, 524288);
        assert_eq!(restored.scanner.scanner_tasks, 25);
        assert_eq!(restored.walker.walker_tasks, 5);
        assert_eq!(restored.discovery.discovery_tasks, 15);
    }

    #[test]
    fn config_round_trip_preserves_optional_fields() {
        // Part A: None fields stay None
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1"]);
        let config = NifflerConfig::from_scan_args(args).unwrap();
        let toml_str = toml::to_string_pretty(&config).expect("serialize");
        let restored: NifflerConfig = toml::from_str(&toml_str).expect("deserialize");
        assert!(restored.rules_dir.is_none());
        assert!(restored.extra_rules.is_none());
        assert!(restored.discovery.nfs_version.is_none());
        assert!(restored.walker.local_paths.is_none());

        // Part B: Some fields preserved
        let args = parse_scan(&[
            "niffler",
            "scan",
            "-t",
            "10.0.0.1",
            "-o",
            "/tmp/results.db",
            "--nfs-version",
            "3",
            "-r",
            "/opt/rules",
            "-R",
            "/opt/extra",
        ]);
        let config = NifflerConfig::from_scan_args(args).unwrap();
        let toml_str = toml::to_string_pretty(&config).expect("serialize");
        let restored: NifflerConfig = toml::from_str(&toml_str).expect("deserialize");
        assert_eq!(restored.output.db_path, PathBuf::from("/tmp/results.db"));
        assert_eq!(restored.discovery.nfs_version, Some(3));
        assert_eq!(restored.rules_dir, Some(PathBuf::from("/opt/rules")));
        assert_eq!(restored.extra_rules, Some(PathBuf::from("/opt/extra")));
    }

    #[test]
    fn config_default_values_serialize_correctly() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1"]);
        let config = NifflerConfig::from_scan_args(args).unwrap();
        let toml_str = toml::to_string_pretty(&config).expect("serialize");
        let restored: NifflerConfig = toml::from_str(&toml_str).expect("deserialize");

        assert_eq!(restored.mode, OperatingMode::Scan);
        assert_eq!(restored.output.db_path, PathBuf::from("niffler.db"));
        assert!(!restored.output.live);
        assert_eq!(restored.min_severity, Triage::Green);
        assert_eq!(restored.scanner.uid, 65534);
        assert_eq!(restored.scanner.gid, 65534);
        assert!(restored.scanner.uid_cycle);
        assert_eq!(restored.scanner.max_uid_attempts, 5);
        assert_eq!(restored.scanner.max_scan_size, 1_048_576);
        assert_eq!(restored.scanner.max_connections_per_host, 8);
        assert_eq!(restored.scanner.scanner_tasks, 50);
        assert!(!restored.scanner.check_subtree_bypass);
        assert_eq!(restored.walker.walker_tasks, 20);
        assert_eq!(restored.walker.max_depth, 50);
        assert_eq!(restored.discovery.discovery_tasks, 30);
        assert!(restored.discovery.privileged_port);
        assert_eq!(restored.discovery.timeout_secs, 5);
        assert!(!restored.generate_config);
    }

    #[test]
    fn export_format_display() {
        assert_eq!(ExportFormat::Json.to_string(), "json");
        assert_eq!(ExportFormat::Csv.to_string(), "csv");
        assert_eq!(ExportFormat::Tsv.to_string(), "tsv");
    }

    #[test]
    fn export_format_value_enum() {
        use clap::ValueEnum;
        let json = ExportFormat::from_str("json", false).unwrap();
        assert_eq!(json, ExportFormat::Json);
        let csv = ExportFormat::from_str("csv", false).unwrap();
        assert_eq!(csv, ExportFormat::Csv);
        let tsv = ExportFormat::from_str("tsv", false).unwrap();
        assert_eq!(tsv, ExportFormat::Tsv);
    }

    #[test]
    fn config_discovery_timeout_default_is_five() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1"]);
        let config = NifflerConfig::from_scan_args(args).unwrap();
        assert_eq!(config.discovery.timeout_secs, 5);
    }

    #[test]
    fn config_discovery_timeout_overridable() {
        let args = parse_scan(&[
            "niffler",
            "scan",
            "-t",
            "10.0.0.1",
            "--discovery-timeout",
            "15",
        ]);
        let config = NifflerConfig::from_scan_args(args).unwrap();
        assert_eq!(config.discovery.timeout_secs, 15);
    }
}
