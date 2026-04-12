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
    #[must_use]
    pub const fn runs_walker(&self) -> bool {
        matches!(self, Self::Enumerate | Self::Scan)
    }

    /// Returns `true` if this mode reads file content for scanning.
    #[must_use]
    pub const fn runs_content_scan(&self) -> bool {
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
    pub connect_timeout_secs: u64,
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
    pub walk_retries: usize,
    pub walk_retry_delay_ms: u64,
    pub uid_cycle: bool,
    pub max_uid_attempts: usize,
    pub connect_timeout_secs: u64,
    pub nfs_timeout_secs: u64,
    pub parallel_dirs: usize,
}

/// File scanner settings — content reading, UID cycling, connection limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    pub scanner_tasks: usize,
    pub max_scan_size: u64,
    pub read_chunk_size: u32,
    pub uid: u32,
    pub gid: u32,
    pub uid_cycle: bool,
    pub max_uid_attempts: usize,
    pub max_connections_per_host: usize,
    pub check_subtree_bypass: bool,
    pub connect_timeout_secs: u64,
    pub nfs_timeout_secs: u64,
    pub task_timeout_secs: u64,
    pub scan_retries: usize,
    pub scan_retry_delay_ms: u64,
}

/// Output settings — SQLite database path and optional live console tee.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub db_path: PathBuf,
    pub live: bool,
    pub min_severity: Triage,
}

/// Host health / circuit breaker settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthConfig {
    pub error_threshold: u32,
    pub cooldown_secs: u64,
}

/// Merged configuration consumed by `run_pipeline()` and all downstream phases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NifflerConfig {
    pub mode: OperatingMode,
    pub discovery: DiscoveryConfig,
    pub walker: WalkerConfig,
    pub scanner: ScannerConfig,
    pub output: OutputConfig,
    pub health: HealthConfig,
    pub rules_dir: Option<PathBuf>,
    pub extra_rules: Option<PathBuf>,
    pub generate_config: bool,
}

impl NifflerConfig {
    /// Build a `NifflerConfig` from parsed scan subcommand arguments.
    ///
    /// If `--config <path>` is provided, the TOML file is deserialized
    /// directly as the config. All CLI flags are ignored when `--config`
    /// is used — generate a base config with `-z`, edit it, then load with `-c`.
    ///
    /// Validates that at least one target source is provided unless `-z` is set.
    pub fn from_scan_args(args: ScanArgs) -> Result<Self> {
        // Bug 2.2: validate --nfs-version early, before any config loading.
        if let Some(v) = args.nfs_version
            && v != 3
            && v != 4
        {
            bail!("invalid --nfs-version {v}: must be 3 or 4");
        }

        // Bug 2.1: if --config is provided, load the TOML file as the config.
        if let Some(ref config_path) = args.config {
            let contents = std::fs::read_to_string(config_path).map_err(|e| {
                anyhow::anyhow!(
                    "failed to read config file '{}': {e}",
                    config_path.display()
                )
            })?;
            let config: Self = toml::from_str(&contents).map_err(|e| {
                anyhow::anyhow!(
                    "failed to parse config file '{}': {e}",
                    config_path.display()
                )
            })?;

            // Validate loaded config: must have targets unless -z
            if config.discovery.targets.is_none()
                && config.discovery.target_file.is_none()
                && config.walker.local_paths.is_none()
                && !config.generate_config
            {
                bail!(
                    "config file '{}' has no targets: set discovery.targets, \
                     discovery.target_file, or walker.local_paths",
                    config_path.display()
                );
            }

            if let Some(v) = config.discovery.nfs_version
                && v != 3
                && v != 4
            {
                bail!(
                    "config file '{}': invalid nfs_version {v}: must be 3 or 4",
                    config_path.display()
                );
            }

            return Ok(config);
        }

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
                privileged_port: !args.no_privileged_port,
                discovery_tasks: args.discovery_tasks,
                timeout_secs: args.discovery_timeout,
                connect_timeout_secs: args.connect_timeout,
                proxy,
            },
            walker: WalkerConfig {
                walker_tasks: args.walker_tasks,
                max_depth: args.max_depth,
                local_paths: args.local_path,
                max_connections_per_host: args.max_connections_per_host,
                walk_retries: args.walk_retries,
                walk_retry_delay_ms: args.walk_retry_delay,
                uid_cycle: !args.no_uid_cycle,
                max_uid_attempts: args.max_uid_attempts,
                connect_timeout_secs: args.connect_timeout,
                nfs_timeout_secs: args.nfs_timeout,
                parallel_dirs: args.parallel_dirs,
            },
            scanner: ScannerConfig {
                scanner_tasks: args.scanner_tasks,
                max_scan_size: args.max_scan_size,
                read_chunk_size: args.read_chunk_size,
                uid: args.uid,
                gid: args.gid,
                uid_cycle: !args.no_uid_cycle,
                max_uid_attempts: args.max_uid_attempts,
                max_connections_per_host: args.max_connections_per_host,
                check_subtree_bypass: args.check_subtree_bypass,
                connect_timeout_secs: args.connect_timeout,
                nfs_timeout_secs: args.nfs_timeout,
                task_timeout_secs: args.task_timeout,
                scan_retries: args.scan_retries,
                scan_retry_delay_ms: args.scan_retry_delay,
            },
            output: OutputConfig {
                db_path: args.output,
                live: args.live,
                min_severity: args.min_severity,
            },
            health: HealthConfig {
                error_threshold: args.error_threshold,
                cooldown_secs: args.cooldown_secs,
            },
            rules_dir: args.rules_dir,
            extra_rules: args.extra_rules,
            generate_config: args.generate_config,
        })
    }
}

/// Parse a proxy URL like `socks5://host:port` or `host:port` into a `SocketAddr`.
///
/// Supports both numeric IPs (`127.0.0.1:1080`) and hostnames (`localhost:1080`).
/// Hostname resolution uses blocking DNS via [`std::net::ToSocketAddrs`], which is
/// acceptable here because this runs once during config parsing, not in a hot path.
fn parse_proxy_url(url: &str) -> Result<SocketAddr> {
    let addr_str = url
        .strip_prefix("socks5://")
        .or_else(|| url.strip_prefix("socks://"))
        .unwrap_or(url);
    use std::net::ToSocketAddrs;
    addr_str
        .to_socket_addrs()
        .map_err(|e| anyhow::anyhow!("invalid proxy address '{addr_str}': {e}"))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve proxy address '{addr_str}'"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::cli::{Cli, NifflerCommand};
    use clap::Parser;

    fn parse_scan(args: &[&str]) -> ScanArgs {
        let cli = Cli::try_parse_from(args).expect("failed to parse CLI args");
        match cli.command {
            NifflerCommand::Scan(args) => *args,
            _ => panic!("expected Scan subcommand"),
        }
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
        assert_eq!(config.walker.walk_retries, 2);
        assert_eq!(config.walker.walk_retry_delay_ms, 500);
        assert_eq!(config.scanner.scanner_tasks, 50);
        assert_eq!(config.output.min_severity, Triage::Green);
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
        assert_eq!(restored.output.min_severity, config.output.min_severity);
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

        // Nested fields
        let discovery = table["discovery"].as_table().unwrap();
        assert!(
            discovery.contains_key("discovery_tasks"),
            "missing: discovery_tasks"
        );

        let walker = table["walker"].as_table().unwrap();
        assert!(walker.contains_key("max_depth"), "missing: max_depth");
        assert!(walker.contains_key("walker_tasks"), "missing: walker_tasks");
        assert!(walker.contains_key("walk_retries"), "missing: walk_retries");
        assert!(
            walker.contains_key("walk_retry_delay_ms"),
            "missing: walk_retry_delay_ms"
        );

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

        // Triage serializes as PascalCase string (no rename_all) — now in output section
        let output = table["output"].as_table().unwrap();
        let severity = &output["min_severity"];
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
        assert_eq!(restored.output.min_severity, Triage::Red);
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
        assert_eq!(restored.output.min_severity, Triage::Green);
        assert_eq!(restored.scanner.uid, 65534);
        assert_eq!(restored.scanner.gid, 65534);
        assert!(restored.scanner.uid_cycle);
        assert_eq!(restored.scanner.max_uid_attempts, 5);
        assert_eq!(restored.scanner.max_scan_size, 1_048_576);
        assert_eq!(restored.scanner.read_chunk_size, 1_048_576);
        assert_eq!(restored.scanner.max_connections_per_host, 8);
        assert_eq!(restored.scanner.scanner_tasks, 50);
        assert!(!restored.scanner.check_subtree_bypass);
        assert_eq!(restored.walker.walker_tasks, 20);
        assert_eq!(restored.walker.walk_retries, 2);
        assert_eq!(restored.walker.walk_retry_delay_ms, 500);
        assert_eq!(restored.walker.max_depth, 50);
        assert_eq!(restored.discovery.discovery_tasks, 30);
        assert!(restored.discovery.privileged_port);
        assert_eq!(restored.discovery.timeout_secs, 5);
        assert_eq!(restored.discovery.connect_timeout_secs, 10);
        assert_eq!(restored.walker.connect_timeout_secs, 10);
        assert_eq!(restored.scanner.connect_timeout_secs, 10);
        assert!(!restored.generate_config);
    }

    // ── Bug 2.1: --config file loading ──────────────────────────────

    #[test]
    fn config_from_file_loads_valid_toml() {
        // Generate a valid config TOML, write to tempfile, load via --config
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1", "--live"]);
        let original = NifflerConfig::from_scan_args(args).unwrap();
        let toml_str = toml::to_string_pretty(&original).expect("serialize");

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("test_config.toml");
        std::fs::write(&config_path, &toml_str).unwrap();

        let args = parse_scan(&["niffler", "scan", "-c", config_path.to_str().unwrap()]);
        let loaded = NifflerConfig::from_scan_args(args).unwrap();
        assert_eq!(loaded.mode, original.mode);
        assert!(loaded.output.live);
        assert_eq!(loaded.scanner.max_scan_size, original.scanner.max_scan_size);
        assert_eq!(
            loaded.discovery.targets.as_deref(),
            original.discovery.targets.as_deref()
        );
    }

    #[test]
    fn config_from_file_missing_file_errors() {
        let args = parse_scan(&[
            "niffler",
            "scan",
            "-c",
            "/tmp/niffler_nonexistent_12345.toml",
        ]);
        let result = NifflerConfig::from_scan_args(args);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("failed to read config file"),
            "expected read error, got: {err}"
        );
    }

    #[test]
    fn config_from_file_invalid_toml_errors() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("bad.toml");
        std::fs::write(&config_path, "this is not valid { toml !!!").unwrap();

        let args = parse_scan(&["niffler", "scan", "-c", config_path.to_str().unwrap()]);
        let result = NifflerConfig::from_scan_args(args);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("failed to parse config file"),
            "expected parse error, got: {err}"
        );
    }

    #[test]
    fn config_from_file_no_targets_errors() {
        // A config file with no targets and generate_config = false should fail
        let args = parse_scan(&["niffler", "scan", "-z"]);
        let mut config = NifflerConfig::from_scan_args(args).unwrap();
        config.generate_config = false;
        config.discovery.targets = None;
        config.discovery.target_file = None;
        config.walker.local_paths = None;
        let toml_str = toml::to_string_pretty(&config).expect("serialize");

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("no_targets.toml");
        std::fs::write(&config_path, &toml_str).unwrap();

        let args = parse_scan(&["niffler", "scan", "-c", config_path.to_str().unwrap()]);
        let result = NifflerConfig::from_scan_args(args);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("no targets"),
            "expected no-targets error, got: {err}"
        );
    }

    // ── Bug 2.2: --nfs-version validation ───────────────────────────

    #[test]
    fn nfs_version_3_accepted() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1", "--nfs-version", "3"]);
        let config = NifflerConfig::from_scan_args(args).unwrap();
        assert_eq!(config.discovery.nfs_version, Some(3));
    }

    #[test]
    fn nfs_version_4_accepted() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1", "--nfs-version", "4"]);
        let config = NifflerConfig::from_scan_args(args).unwrap();
        assert_eq!(config.discovery.nfs_version, Some(4));
    }

    #[test]
    fn nfs_version_invalid_rejected() {
        for v in ["0", "1", "2", "5", "99", "255"] {
            let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1", "--nfs-version", v]);
            let result = NifflerConfig::from_scan_args(args);
            assert!(result.is_err(), "--nfs-version {v} should be rejected");
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("invalid --nfs-version"),
                "expected nfs-version error for {v}, got: {err}"
            );
        }
    }

    #[test]
    fn nfs_version_none_accepted() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1"]);
        let config = NifflerConfig::from_scan_args(args).unwrap();
        assert_eq!(config.discovery.nfs_version, None);
    }

    // ── Bug 2.3: parse_proxy_url hostname support ───────────────────

    #[test]
    fn proxy_url_with_scheme_numeric() {
        let addr = parse_proxy_url("socks5://127.0.0.1:1080").unwrap();
        assert_eq!(addr.ip(), std::net::Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(addr.port(), 1080);
    }

    #[test]
    fn proxy_url_bare_ip_port() {
        let addr = parse_proxy_url("127.0.0.1:1080").unwrap();
        assert_eq!(addr.port(), 1080);
    }

    #[test]
    fn proxy_url_bare_localhost_resolves() {
        let addr = parse_proxy_url("localhost:1080").unwrap();
        assert_eq!(addr.port(), 1080);
        assert!(addr.ip().is_loopback());
    }

    #[test]
    fn proxy_url_invalid_errors() {
        let result = parse_proxy_url("not-a-valid-address");
        assert!(result.is_err());
    }
}
