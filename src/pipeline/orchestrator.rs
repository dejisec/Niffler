use std::sync::Arc;

use indicatif::MultiProgress;
use tokio_util::sync::CancellationToken;

use crate::classifier::{RuleEngine, load_embedded_defaults, load_rules_from_dir, merge_rules};
use crate::config::NifflerConfig;
use crate::nfs::{AuthCreds, AuthStrategy, NfsConnector};
use crate::{discovery, output, scanner, walker};

use super::channels::PipelineChannels;
use super::connections::HostConnectionPool;
use super::error::PipelineError;
use super::health::HostHealthRegistry;
use super::progress::ProgressDisplay;
use super::stats::PipelineStats;

/// Load and compile the rule engine from config.
fn build_rules(config: &NifflerConfig) -> Result<RuleEngine, PipelineError> {
    let mut rules = if let Some(ref dir) = config.rules_dir {
        // -r replaces defaults entirely
        load_rules_from_dir(dir).map_err(|e| PipelineError::Config(e.to_string()))?
    } else {
        load_embedded_defaults().map_err(|e| PipelineError::Config(e.to_string()))?
    };

    if let Some(ref dir) = config.extra_rules {
        let extra = load_rules_from_dir(dir).map_err(|e| PipelineError::Config(e.to_string()))?;
        rules = merge_rules(rules, extra);
    }

    let engine = RuleEngine::compile(rules).map_err(|e| PipelineError::Config(e.to_string()))?;
    engine
        .validate_relay_targets()
        .map_err(|e| PipelineError::Config(e.to_string()))?;
    engine
        .detect_relay_cycles()
        .map_err(|e| PipelineError::Config(e.to_string()))?;
    engine
        .validate_scope_location()
        .map_err(|e| PipelineError::Config(e.to_string()))?;

    Ok(engine)
}

/// Wire all pipeline phases together and run to completion.
///
/// - `connector` is shared by walker + scanner for NFS operations.
/// - `cancel`: `None` creates an internal token with Ctrl+C handler;
///   `Some(token)` uses the provided token (for testing).
pub async fn run_pipeline(
    config: NifflerConfig,
    connector: Arc<dyn NfsConnector>,
    cancel: Option<CancellationToken>,
    multi: Option<MultiProgress>,
) -> Result<PipelineStats, PipelineError> {
    let rules = Arc::new(build_rules(&config)?);
    let channels = PipelineChannels::default();
    let stats = Arc::new(PipelineStats::default());

    let token = cancel.unwrap_or_else(|| {
        let t = CancellationToken::new();
        let t2 = t.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            t2.cancel();
        });
        t
    });

    // Build auth strategy from config
    let default_creds = AuthCreds::new(config.scanner.uid, config.scanner.gid);
    let auth = AuthStrategy {
        primary: default_creds.clone(),
        harvested: vec![],
        auto_cycle: config.scanner.uid_cycle,
        max_attempts: config.scanner.max_uid_attempts,
    };

    // Progress bars — caller passes Some(MultiProgress) when enabled
    let progress = Arc::new(ProgressDisplay::new(multi));

    // Spawn progress updater task
    let progress_handle = {
        let stats = Arc::clone(&stats);
        let progress = Arc::clone(&progress);
        let token = token.clone();
        tokio::spawn(async move {
            while !token.is_cancelled() {
                progress.update_from_stats(&stats);
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
        })
    };

    let config = Arc::new(config);
    let mode = config.mode;

    // Phase 1: Discovery (always runs)
    let discovery_handle = {
        let export_tx = channels.export_tx.clone();
        let result_tx = channels.result_tx.clone();
        let token = token.clone();
        let stats = Arc::clone(&stats);
        let config = Arc::clone(&config);
        let rules = Arc::clone(&rules);
        tokio::spawn(async move {
            discovery::run(&config, export_tx, result_tx, token, stats, rules).await
        })
    };

    // Shared infrastructure for walker + scanner
    let health = Arc::new(HostHealthRegistry::default());
    let conn_pool = Arc::new(HostConnectionPool::new(
        config.scanner.max_connections_per_host,
    ));

    // Phase 2: TreeWalk (runs in enumerate + scan modes)
    let walker_handle = if mode.runs_walker() {
        let file_tx = channels.file_tx.clone();
        let connector = Arc::clone(&connector);
        let rules = Arc::clone(&rules);
        let token = token.clone();
        let stats = Arc::clone(&stats);
        let walker_config = config.walker.clone();
        let creds = default_creds.clone();
        let walker_conn_pool = Arc::new(HostConnectionPool::new(
            config.walker.max_connections_per_host,
        ));
        let walker_health = Arc::clone(&health);
        Some(tokio::spawn(async move {
            walker::run(
                channels.export_rx,
                file_tx,
                connector,
                rules,
                &walker_config,
                creds,
                token,
                stats,
                walker_conn_pool,
                walker_health,
            )
            .await
        }))
    } else {
        drop(channels.export_rx);
        None
    };

    // Phase 3: FileScanner (runs in enumerate + scan modes to consume file_rx)
    let scanner_handle = if mode.runs_walker() {
        let result_tx = channels.result_tx.clone();
        let rules = Arc::clone(&rules);
        let connector = Arc::clone(&connector);
        let auth = auth.clone();
        let token = token.clone();
        let stats = Arc::clone(&stats);
        let scanner_config = config.scanner.clone();
        let health = Arc::clone(&health);
        let conn_pool = Arc::clone(&conn_pool);
        Some(tokio::spawn(async move {
            scanner::run(
                channels.file_rx,
                result_tx,
                rules,
                connector,
                auth,
                &scanner_config,
                mode,
                token,
                stats,
                health,
                conn_pool,
            )
            .await
        }))
    } else {
        drop(channels.file_rx);
        None
    };

    // Output sink (always runs — drains result_rx, writes SQLite + optional console)
    let output_handle = {
        let output_config = config.output.clone();
        let mut targets = config.discovery.targets.clone().unwrap_or_default();
        if let Some(ref paths) = config.walker.local_paths {
            targets.extend(paths.iter().map(|p| p.display().to_string()));
        }
        let mode_str = config.mode.to_string();
        let stats = Arc::clone(&stats);
        tokio::spawn(async move {
            output::run(
                channels.result_rx,
                &output_config,
                &targets,
                &mode_str,
                stats,
            )
            .await
        })
    };

    // Sequential await with sender drops for graceful channel closure.
    // Each phase await races against the cancellation token so Ctrl+C
    // doesn't block on a hung phase.
    tokio::select! {
        result = discovery_handle => {
            result.map_err(PipelineError::from)?
                  .map_err(|e| PipelineError::PhaseFailed(e.to_string()))?;
        }
        _ = token.cancelled() => {}
    }
    drop(channels.export_tx);

    if let Some(handle) = walker_handle {
        tokio::select! {
            result = handle => {
                result.map_err(PipelineError::from)?
                      .map_err(|e| PipelineError::PhaseFailed(e.to_string()))?;
            }
            _ = token.cancelled() => {}
        }
    }
    drop(channels.file_tx);

    if let Some(handle) = scanner_handle {
        tokio::select! {
            result = handle => {
                result.map_err(PipelineError::from)?
                      .map_err(|e| PipelineError::PhaseFailed(e.to_string()))?;
            }
            _ = token.cancelled() => {}
        }
    }
    drop(channels.result_tx);

    // Always await output — all senders are dropped, so it drains quickly
    output_handle
        .await
        .map_err(PipelineError::from)?
        .map_err(|e| PipelineError::PhaseFailed(e.to_string()))?;

    // Finish progress bars and stop updater
    progress.update_from_stats(&stats);
    progress.finish();
    progress_handle.abort();
    let _ = progress_handle.await; // Ensure task's Arc<PipelineStats> is dropped
    drop(progress); // Drop the Arc<ProgressDisplay>

    Ok(match Arc::try_unwrap(stats) {
        Ok(s) => s,
        Err(arc) => {
            tracing::debug!("stats Arc still shared at shutdown, snapshotting counters");
            arc.snapshot()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::classifier::Triage;
    use crate::config::{
        DiscoveryConfig, OperatingMode, OutputConfig, ScannerConfig, WalkerConfig,
    };
    use crate::nfs::connector::MockNfsConnector;

    fn test_config(mode: OperatingMode) -> NifflerConfig {
        NifflerConfig {
            mode,
            discovery: DiscoveryConfig {
                targets: None,
                target_file: None,
                nfs_version: None,
                privileged_port: false,
                discovery_tasks: 10,
                timeout_secs: 5,
                proxy: None,
            },
            walker: WalkerConfig {
                walker_tasks: 10,
                max_depth: 50,
                local_paths: None,
                max_connections_per_host: 8,
            },
            scanner: ScannerConfig {
                scanner_tasks: 10,
                max_scan_size: 1_048_576,
                uid: 65534,
                gid: 65534,
                uid_cycle: true,
                max_uid_attempts: 5,
                max_connections_per_host: 8,
                check_subtree_bypass: false,
            },
            output: OutputConfig {
                db_path: std::env::temp_dir().join("niffler_test_pipeline.db"),
                live: false,
                min_severity: Triage::Green,
            },
            rules_dir: None,
            extra_rules: None,
            min_severity: Triage::Green,
            generate_config: false,
        }
    }

    fn mock_connector() -> Arc<dyn NfsConnector> {
        let mock = MockNfsConnector::new();
        Arc::new(mock)
    }

    #[tokio::test]
    async fn run_pipeline_empty_targets_completes() {
        let config = test_config(OperatingMode::Scan);
        let connector = mock_connector();
        let token = CancellationToken::new();

        let result = tokio::time::timeout(
            Duration::from_secs(10),
            run_pipeline(config, connector, Some(token), None),
        )
        .await;

        assert!(result.is_ok(), "pipeline should not timeout");
        let stats = result.unwrap().unwrap();
        assert_eq!(
            stats
                .exports_found
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn run_pipeline_channels_close_sequentially() {
        let config = test_config(OperatingMode::Scan);
        let connector = mock_connector();
        let token = CancellationToken::new();

        let result = tokio::time::timeout(
            Duration::from_secs(10),
            run_pipeline(config, connector, Some(token), None),
        )
        .await;

        assert!(
            result.is_ok(),
            "pipeline should not deadlock — channels must close in order"
        );
        assert!(result.unwrap().is_ok());
    }

    #[tokio::test]
    async fn run_pipeline_config_error_returns_err() {
        // Create a temp dir with an invalid TOML file to trigger parse error
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("bad.toml"), "this is not valid [[toml]]{{").unwrap();

        let mut config = test_config(OperatingMode::Scan);
        config.rules_dir = Some(tmp.path().to_path_buf());
        let connector = mock_connector();
        let token = CancellationToken::new();

        let result = run_pipeline(config, connector, Some(token), None).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PipelineError::Config(_)));
    }

    #[tokio::test]
    async fn run_pipeline_cancellation_completes() {
        let config = test_config(OperatingMode::Scan);
        let connector = mock_connector();
        let token = CancellationToken::new();
        token.cancel();

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            run_pipeline(config, connector, Some(token), None),
        )
        .await;

        assert!(result.is_ok(), "cancelled pipeline should complete quickly");
        assert!(result.unwrap().is_ok());
    }

    #[tokio::test]
    async fn run_pipeline_recon_mode_skips_walker() {
        let config = test_config(OperatingMode::Recon);
        let connector = mock_connector();
        let token = CancellationToken::new();

        let result = tokio::time::timeout(
            Duration::from_secs(10),
            run_pipeline(config, connector, Some(token), None),
        )
        .await;

        assert!(result.is_ok(), "recon pipeline should not timeout");
        let stats = result.unwrap().unwrap();
        assert_eq!(
            stats.dirs_walked.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "walker should not run in recon mode"
        );
        assert_eq!(
            stats
                .files_discovered
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "no files should be discovered in recon mode"
        );
    }

    #[tokio::test]
    async fn run_pipeline_recon_mode_no_findings_on_empty() {
        let config = test_config(OperatingMode::Recon);
        let connector = mock_connector();
        let token = CancellationToken::new();

        let result = run_pipeline(config, connector, Some(token), None).await;
        assert!(result.is_ok());
        let stats = result.unwrap();
        assert_eq!(
            stats.findings.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "no findings with empty targets"
        );
    }

    #[tokio::test]
    async fn run_pipeline_enumerate_mode_completes() {
        let config = test_config(OperatingMode::Enumerate);
        let connector = mock_connector();
        let token = CancellationToken::new();

        let result = tokio::time::timeout(
            Duration::from_secs(10),
            run_pipeline(config, connector, Some(token), None),
        )
        .await;

        assert!(
            result.is_ok(),
            "enumerate pipeline should not deadlock with empty targets"
        );
        assert!(result.unwrap().is_ok());
    }

    #[tokio::test]
    async fn run_pipeline_recon_mode_drops_channels_cleanly() {
        let config = test_config(OperatingMode::Recon);
        let connector = mock_connector();
        let token = CancellationToken::new();

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            run_pipeline(config, connector, Some(token), None),
        )
        .await;

        assert!(
            result.is_ok(),
            "recon mode should drop channels cleanly and complete quickly"
        );
        assert!(result.unwrap().is_ok());
    }

    #[tokio::test]
    async fn run_pipeline_cancellation_stops_phases() {
        let config = test_config(OperatingMode::Scan);
        let connector = mock_connector();
        let token = CancellationToken::new();
        let token2 = token.clone();

        // Cancel after a short delay
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            token2.cancel();
        });

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            run_pipeline(config, connector, Some(token), None),
        )
        .await;

        assert!(result.is_ok(), "cancelled pipeline should not deadlock");
        assert!(
            result.unwrap().is_ok(),
            "cancellation is graceful — returns Ok, not Err"
        );
    }

    #[tokio::test]
    async fn run_pipeline_cancellation_returns_ok_not_error() {
        let config = test_config(OperatingMode::Scan);
        let connector = mock_connector();
        let token = CancellationToken::new();
        token.cancel();

        let result = run_pipeline(config, connector, Some(token), None).await;
        assert!(
            result.is_ok(),
            "cancellation should return Ok(stats), not Err: {:?}",
            result.err()
        );
    }

    #[test]
    fn build_rules_with_rules_dir_replaces_defaults() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("custom.toml"),
            r#"
[[rules]]
name = "OnlyCustomRule"
scope = "FileEnumeration"
match_location = "FileName"
match_type = "Exact"
patterns = ["custom_file"]
action = "Snaffle"
triage = "Green"
"#,
        )
        .unwrap();

        let mut config = test_config(OperatingMode::Scan);
        config.rules_dir = Some(tmp.path().to_path_buf());

        let engine = build_rules(&config).unwrap();
        assert_eq!(
            engine.rule_count(),
            1,
            "rules_dir should REPLACE defaults, not merge. Got {} rules",
            engine.rule_count()
        );
        assert!(engine.matcher("OnlyCustomRule").is_some());
    }

    #[test]
    fn build_rules_with_extra_rules_merges_with_defaults() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("extra.toml"),
            r#"
[[rules]]
name = "ExtraRule"
scope = "FileEnumeration"
match_location = "FileName"
match_type = "Exact"
patterns = ["extra_file"]
action = "Snaffle"
triage = "Yellow"
"#,
        )
        .unwrap();

        let mut config = test_config(OperatingMode::Scan);
        config.extra_rules = Some(tmp.path().to_path_buf());

        let engine = build_rules(&config).unwrap();
        assert!(
            engine.rule_count() > 1,
            "extra_rules should MERGE with defaults"
        );
        assert!(engine.matcher("ExtraRule").is_some());
    }

    #[tokio::test]
    async fn check_subtree_bypass_flag_accepted() {
        let mut config = test_config(OperatingMode::Recon);
        config.scanner.check_subtree_bypass = true;
        let connector = mock_connector();
        let token = CancellationToken::new();

        let result = run_pipeline(config, connector, Some(token), None).await;
        assert!(
            result.is_ok(),
            "check_subtree_bypass flag should be accepted: {result:?}"
        );
    }

    #[test]
    fn build_rules_rejects_invalid_scope_location() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("bad_scope.toml"),
            r#"
[[rules]]
name = "BadShareFileName"
scope = "ShareEnumeration"
match_location = "FileName"
match_type = "Exact"
patterns = ["foo"]
action = "Snaffle"
triage = "Green"
"#,
        )
        .unwrap();

        let mut config = test_config(OperatingMode::Scan);
        config.rules_dir = Some(tmp.path().to_path_buf());

        let result = build_rules(&config);
        let err = result
            .err()
            .expect("invalid scope/location should be rejected");
        let msg = err.to_string();
        assert!(msg.contains("invalid scope/location"), "error: {msg}");
    }

    #[tokio::test]
    async fn run_pipeline_cancellation_token_propagated() {
        let config = test_config(OperatingMode::Scan);
        let connector = mock_connector();
        let token = CancellationToken::new();
        token.cancel();

        let result = tokio::time::timeout(
            Duration::from_secs(1),
            run_pipeline(config, connector, Some(token), None),
        )
        .await;

        assert!(
            result.is_ok(),
            "token must be propagated — pipeline should exit within 1 second"
        );
        assert!(result.unwrap().is_ok());
    }
}
