use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::classifier::Triage;
use crate::config::cli::Cli;

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

/// Selects the output format for scan results.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    /// Colored terminal output with severity indicators.
    #[default]
    Console,
    /// One JSON object per finding (JSON Lines).
    Json,
    /// Tab-separated values compatible with Snaffler parsers.
    Tsv,
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

/// Output settings — format selection and file destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub format: OutputFormat,
    pub output_file: Option<PathBuf>,
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
    /// Build a `NifflerConfig` from parsed CLI arguments.
    ///
    /// Validates that at least one target source is provided unless `-z` is set.
    pub fn from_cli(cli: Cli) -> Result<Self> {
        if cli.targets.is_none()
            && cli.target_file.is_none()
            && cli.local_path.is_none()
            && !cli.generate_config
        {
            bail!(
                "no targets specified: provide -t <targets>, -T <file>, -i <path>, or -z to generate config"
            );
        }

        let proxy = cli.proxy.as_deref().map(parse_proxy_url).transpose()?;

        Ok(Self {
            mode: cli.mode,
            discovery: DiscoveryConfig {
                targets: cli.targets,
                target_file: cli.target_file,
                nfs_version: cli.nfs_version,
                privileged_port: cli.privileged_port,
                discovery_tasks: cli.discovery_tasks,
                timeout_secs: cli.discovery_timeout,
                proxy,
            },
            walker: WalkerConfig {
                walker_tasks: cli.walker_tasks,
                max_depth: cli.max_depth,
                local_paths: cli.local_path,
                max_connections_per_host: cli.max_connections_per_host,
            },
            scanner: ScannerConfig {
                scanner_tasks: cli.scanner_tasks,
                max_scan_size: cli.max_scan_size,
                uid: cli.uid,
                gid: cli.gid,
                uid_cycle: cli.uid_cycle,
                max_uid_attempts: cli.max_uid_attempts,
                max_connections_per_host: cli.max_connections_per_host,
                check_subtree_bypass: cli.check_subtree_bypass,
            },
            output: OutputConfig {
                format: cli.format,
                output_file: cli.output,
                min_severity: cli.min_severity,
            },
            rules_dir: cli.rules_dir,
            extra_rules: cli.extra_rules,
            min_severity: cli.min_severity,
            generate_config: cli.generate_config,
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
    use clap::Parser;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("failed to parse CLI args")
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
    fn config_from_cli_with_defaults() {
        let cli = parse(&["niffler", "-t", "10.0.0.1"]);
        let config = NifflerConfig::from_cli(cli).unwrap();
        assert_eq!(config.mode, OperatingMode::Scan);
        assert_eq!(config.output.format, OutputFormat::Console);
        assert_eq!(config.scanner.max_scan_size, 1_048_576);
        assert_eq!(config.discovery.discovery_tasks, 30);
        assert_eq!(config.walker.walker_tasks, 20);
        assert_eq!(config.scanner.scanner_tasks, 50);
        assert_eq!(config.min_severity, Triage::Green);
    }

    #[test]
    fn config_from_cli_maps_discovery() {
        let cli = parse(&[
            "niffler",
            "-t",
            "10.0.0.1",
            "192.168.1.0/24",
            "--nfs-version",
            "3",
            "--privileged-port",
        ]);
        let config = NifflerConfig::from_cli(cli).unwrap();
        let targets = config.discovery.targets.unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0], "10.0.0.1");
        assert_eq!(targets[1], "192.168.1.0/24");
        assert_eq!(config.discovery.nfs_version, Some(3));
        assert!(config.discovery.privileged_port);
    }

    #[test]
    fn config_from_cli_maps_scanner() {
        let cli = parse(&[
            "niffler",
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
        let config = NifflerConfig::from_cli(cli).unwrap();
        assert_eq!(config.scanner.uid, 1000);
        assert_eq!(config.scanner.gid, 1000);
        assert_eq!(config.scanner.max_scan_size, 2_097_152);
        assert!(config.scanner.uid_cycle);
        assert_eq!(config.scanner.max_uid_attempts, 10);
    }

    #[test]
    fn config_from_cli_maps_output() {
        let cli = parse(&[
            "niffler",
            "-t",
            "10.0.0.1",
            "-f",
            "json",
            "-o",
            "/tmp/out.json",
        ]);
        let config = NifflerConfig::from_cli(cli).unwrap();
        assert_eq!(config.output.format, OutputFormat::Json);
        assert_eq!(
            config.output.output_file,
            Some(PathBuf::from("/tmp/out.json"))
        );
    }

    #[test]
    fn config_from_cli_no_targets_error() {
        let cli = parse(&["niffler"]);
        let result = NifflerConfig::from_cli(cli);
        assert!(result.is_err());
    }

    #[test]
    fn config_from_cli_local_path_no_targets_ok() {
        let cli = parse(&["niffler", "-i", "/mnt/share"]);
        let result = NifflerConfig::from_cli(cli);
        assert!(result.is_ok());
    }

    #[test]
    fn config_from_cli_generate_config_no_targets_ok() {
        let cli = parse(&["niffler", "-z"]);
        let result = NifflerConfig::from_cli(cli);
        assert!(result.is_ok());
    }

    #[test]
    fn config_toml_round_trip() {
        let cli = parse(&["niffler", "-t", "10.0.0.1", "-f", "json"]);
        let config = NifflerConfig::from_cli(cli).unwrap();
        let toml_str = toml::to_string_pretty(&config).expect("serialize to TOML");
        let restored: NifflerConfig = toml::from_str(&toml_str).expect("deserialize from TOML");
        assert_eq!(restored.mode, config.mode);
        assert_eq!(restored.output.format, config.output.format);
        assert_eq!(restored.scanner.max_scan_size, config.scanner.max_scan_size);
        assert_eq!(restored.min_severity, config.min_severity);
    }

    #[test]
    fn config_serializes_to_valid_toml() {
        let cli = parse(&["niffler", "-t", "10.0.0.1"]);
        let config = NifflerConfig::from_cli(cli).unwrap();
        let toml_str = toml::to_string_pretty(&config).expect("serialize");
        let value: toml::Value = toml::from_str(&toml_str).expect("parse as TOML Value");
        assert!(value.is_table());
    }

    #[test]
    fn config_serialization_contains_all_sections() {
        let cli = parse(&["niffler", "-t", "10.0.0.1"]);
        let config = NifflerConfig::from_cli(cli).unwrap();
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
        let cli = parse(&["niffler", "-t", "10.0.0.1"]);
        let config = NifflerConfig::from_cli(cli).unwrap();
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
        assert!(output.contains_key("format"), "missing: format");
    }

    #[test]
    fn config_serialization_enums_as_strings() {
        let cli = parse(&["niffler", "-t", "10.0.0.1"]);
        let config = NifflerConfig::from_cli(cli).unwrap();
        let toml_str = toml::to_string_pretty(&config).expect("serialize");
        let value: toml::Value = toml::from_str(&toml_str).unwrap();
        let table = value.as_table().unwrap();

        // OperatingMode serializes as lowercase string
        let mode = &table["mode"];
        assert_eq!(mode.as_str().unwrap(), "scan");
        assert!(mode.as_integer().is_none(), "mode should not be an integer");

        // OutputFormat serializes as lowercase string
        let format = &table["output"].as_table().unwrap()["format"];
        assert_eq!(format.as_str().unwrap(), "console");
        assert!(
            format.as_integer().is_none(),
            "format should not be an integer"
        );

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
        let cli = parse(&[
            "niffler",
            "-t",
            "10.0.0.1",
            "-m",
            "recon",
            "-f",
            "tsv",
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
        let config = NifflerConfig::from_cli(cli).unwrap();
        let toml_str = toml::to_string_pretty(&config).expect("serialize");
        let restored: NifflerConfig = toml::from_str(&toml_str).expect("deserialize");

        assert_eq!(restored.mode, OperatingMode::Recon);
        assert_eq!(restored.output.format, OutputFormat::Tsv);
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
        let cli = parse(&["niffler", "-t", "10.0.0.1"]);
        let config = NifflerConfig::from_cli(cli).unwrap();
        let toml_str = toml::to_string_pretty(&config).expect("serialize");
        let restored: NifflerConfig = toml::from_str(&toml_str).expect("deserialize");
        assert!(restored.rules_dir.is_none());
        assert!(restored.extra_rules.is_none());
        assert!(restored.output.output_file.is_none());
        assert!(restored.discovery.nfs_version.is_none());
        assert!(restored.walker.local_paths.is_none());

        // Part B: Some fields preserved
        let cli = parse(&[
            "niffler",
            "-t",
            "10.0.0.1",
            "-o",
            "/tmp/out.json",
            "--nfs-version",
            "3",
            "-r",
            "/opt/rules",
            "-R",
            "/opt/extra",
        ]);
        let config = NifflerConfig::from_cli(cli).unwrap();
        let toml_str = toml::to_string_pretty(&config).expect("serialize");
        let restored: NifflerConfig = toml::from_str(&toml_str).expect("deserialize");
        assert_eq!(
            restored.output.output_file,
            Some(PathBuf::from("/tmp/out.json"))
        );
        assert_eq!(restored.discovery.nfs_version, Some(3));
        assert_eq!(restored.rules_dir, Some(PathBuf::from("/opt/rules")));
        assert_eq!(restored.extra_rules, Some(PathBuf::from("/opt/extra")));
    }

    #[test]
    fn config_default_values_serialize_correctly() {
        let cli = parse(&["niffler", "-t", "10.0.0.1"]);
        let config = NifflerConfig::from_cli(cli).unwrap();
        let toml_str = toml::to_string_pretty(&config).expect("serialize");
        let restored: NifflerConfig = toml::from_str(&toml_str).expect("deserialize");

        assert_eq!(restored.mode, OperatingMode::Scan);
        assert_eq!(restored.output.format, OutputFormat::Console);
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
        assert!(!restored.discovery.privileged_port);
        assert_eq!(restored.discovery.timeout_secs, 5);
        assert!(!restored.generate_config);
    }

    #[test]
    fn config_discovery_timeout_default_is_five() {
        let cli = parse(&["niffler", "-t", "10.0.0.1"]);
        let config = NifflerConfig::from_cli(cli).unwrap();
        assert_eq!(config.discovery.timeout_secs, 5);
    }

    #[test]
    fn config_discovery_timeout_overridable() {
        let cli = parse(&["niffler", "-t", "10.0.0.1", "--discovery-timeout", "15"]);
        let config = NifflerConfig::from_cli(cli).unwrap();
        assert_eq!(config.discovery.timeout_secs, 15);
    }
}
