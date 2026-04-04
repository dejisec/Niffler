use std::sync::atomic::Ordering;

use chrono::{DateTime, Utc};

use crate::classifier::{FileEntry, Finding, MatchLocation, RuleEngine, Triage};
use crate::config::OperatingMode;
use crate::nfs::{AuthCreds, AuthStrategy, ErrorClass, NfsAttrs, NfsConnector, NfsFh};
use crate::pipeline::{FileMsg, FileReader, HostHealthRegistry, PipelineStats, ResultMsg};

use super::cache::ConnectionCache;
use super::content::{is_likely_binary, read_for_scan, read_local_for_scan};
use super::context::{extract_context, extract_context_bytes};
use super::error::ScannerError;
use super::keys::inspect_key_material;

/// Read file content with 3-tier UID cycling: primary → owner → harvested.
/// On PermissionDenied, cycles to next credential set. Other errors propagate immediately.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn read_with_uid_cycling(
    connector: &dyn NfsConnector,
    host: &str,
    export: &str,
    fh: &NfsFh,
    attrs: &NfsAttrs,
    auth: &AuthStrategy,
    conn_cache: &mut ConnectionCache,
    max_scan_size: u64,
) -> Result<Vec<u8>, ScannerError> {
    // 1. Try primary credentials
    let client = conn_cache
        .get_or_connect(connector, host, export, &auth.primary)
        .await?;
    match read_for_scan(client, fh, max_scan_size, attrs.size).await {
        Ok(data) => return Ok(data),
        Err(e) if e.classify() == ErrorClass::PermissionDenied && auth.auto_cycle => {}
        Err(e) => return Err(e),
    }

    // 2. Try owner UID (stat-guided)
    let owner_creds = AuthCreds::new(attrs.uid, attrs.gid);
    if owner_creds != auth.primary {
        let client = conn_cache
            .get_or_connect(connector, host, export, &owner_creds)
            .await?;
        match read_for_scan(client, fh, max_scan_size, attrs.size).await {
            Ok(data) => return Ok(data),
            Err(e) if e.classify() == ErrorClass::PermissionDenied => {}
            Err(e) => return Err(e),
        }
    }

    // 3. Cycle harvested UIDs (count unique attempts, not list position)
    let mut unique_attempts = 0usize;
    for creds in &auth.harvested {
        if *creds == auth.primary || *creds == owner_creds {
            continue;
        }
        if unique_attempts >= auth.max_attempts {
            break;
        }
        unique_attempts += 1;
        let client = conn_cache
            .get_or_connect(connector, host, export, creds)
            .await?;
        match read_for_scan(client, fh, max_scan_size, attrs.size).await {
            Ok(data) => return Ok(data),
            Err(e) if e.classify() == ErrorClass::PermissionDenied => continue,
            Err(e) => return Err(e),
        }
    }

    // 4. All attempts exhausted
    Err(ScannerError::AllUidsFailed(fh.clone()))
}

fn file_entry_from_msg(msg: &FileMsg) -> FileEntry {
    let path = std::path::Path::new(&msg.file_path);
    FileEntry {
        name: path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string(),
        path: msg.file_path.clone(),
        extension: path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_string(),
        size: msg.attrs.size,
        uid: msg.attrs.uid,
        gid: msg.attrs.gid,
        mode: msg.attrs.mode,
    }
}

fn finding_to_result(finding: &Finding, msg: &FileMsg) -> ResultMsg {
    ResultMsg {
        timestamp: Utc::now(),
        host: msg.host.clone(),
        export_path: msg.export_path.clone(),
        file_path: msg.file_path.clone(),
        triage: finding.triage,
        rule_name: finding.rule_name.clone(),
        matched_pattern: finding.matched_pattern.clone(),
        context: finding.context.clone(),
        file_size: msg.attrs.size,
        file_mode: msg.attrs.mode,
        file_uid: msg.attrs.uid,
        file_gid: msg.attrs.gid,
        last_modified: DateTime::from_timestamp(msg.attrs.mtime.min(i64::MAX as u64) as i64, 0)
            .unwrap_or_default(),
    }
}

/// Per-file scan orchestration: name rules → content read → content rules → key inspection.
/// Returns Vec<ResultMsg>, NEVER Err (invariant #7).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn scan_file(
    msg: &FileMsg,
    rules: &RuleEngine,
    connector: &dyn NfsConnector,
    auth: &AuthStrategy,
    mode: OperatingMode,
    max_scan_size: u64,
    conn_cache: &mut ConnectionCache,
    stats: &PipelineStats,
    health: &HostHealthRegistry,
) -> Vec<ResultMsg> {
    let entry = file_entry_from_msg(msg);
    let mut results = Vec::new();

    // 1. Evaluate file-name rules (no content yet)
    let name_findings = rules.evaluate_file(&entry, None);
    for finding in &name_findings {
        results.push(finding_to_result(finding, msg));
    }

    // 2. Mode check — enumerate mode skips content
    if !mode.runs_content_scan() {
        return results;
    }

    // 3. Read file content — merge per-file harvested UIDs into auth strategy
    let file_auth;
    let effective_auth = if !msg.harvested_uids.is_empty() {
        file_auth = AuthStrategy {
            primary: auth.primary.clone(),
            harvested: {
                let mut h = auth.harvested.clone();
                h.extend(msg.harvested_uids.iter().cloned());
                h
            },
            auto_cycle: auth.auto_cycle,
            max_attempts: auth.max_attempts,
        };
        &file_auth
    } else {
        auth
    };

    let data = match &msg.reader {
        FileReader::Nfs { host, export } => {
            match read_with_uid_cycling(
                connector,
                host,
                export,
                &msg.file_handle,
                &msg.attrs,
                effective_auth,
                conn_cache,
                max_scan_size,
            )
            .await
            {
                Ok(data) => {
                    health.record_success(host);
                    data
                }
                Err(e) => {
                    match e.classify() {
                        ErrorClass::PermissionDenied => stats
                            .files_skipped_permission
                            .fetch_add(1, Ordering::Relaxed),
                        ErrorClass::Stale => stats.errors_stale.fetch_add(1, Ordering::Relaxed),
                        ErrorClass::ConnectionLost => {
                            stats.errors_connection.fetch_add(1, Ordering::Relaxed)
                        }
                        _ => stats.errors_transient.fetch_add(1, Ordering::Relaxed),
                    };
                    health.record_error(host);
                    return results;
                }
            }
        }
        FileReader::Local { path } => match read_local_for_scan(path, max_scan_size) {
            Ok(data) => data,
            Err(_) => return results,
        },
    };

    stats.files_content_scanned.fetch_add(1, Ordering::Relaxed);
    stats
        .bytes_read
        .fetch_add(data.len() as u64, Ordering::Relaxed);
    if (data.len() as u64) < msg.attrs.size {
        stats.files_skipped_size.fetch_add(1, Ordering::Relaxed);
    }

    // 4. Binary detection (invariant #8 — tracked for stats)
    let is_binary = is_likely_binary(&data);
    if is_binary {
        stats.files_skipped_binary.fetch_add(1, Ordering::Relaxed);
    }

    // 5. Evaluate content rules (engine handles binary detection internally)
    // Re-evaluate with content — this re-runs file rules but also follows relay chains to content rules.
    // Deduplicate: skip findings already found in the name-only pass.
    let name_rule_names: Vec<String> = name_findings.iter().map(|f| f.rule_name.clone()).collect();
    let content_findings = rules.evaluate_file(&entry, Some(&data));
    let text = String::from_utf8_lossy(&data);
    for finding in &content_findings {
        if name_rule_names.contains(&finding.rule_name) {
            continue; // Already emitted from name-only pass
        }
        let mut result = finding_to_result(finding, msg);
        let is_bytes_rule = rules
            .match_location(&finding.rule_name)
            .is_some_and(|loc| *loc == MatchLocation::FileContentAsBytes);
        if is_bytes_rule {
            let ctx_bytes = rules.context_bytes(&finding.rule_name).unwrap_or(200);
            if let Some((start, end)) = rules
                .matcher(&finding.rule_name)
                .and_then(|m| m.find_match_bytes(&data))
            {
                result.context = Some(extract_context_bytes(&data, start, end, ctx_bytes));
            } else {
                let context_len = data.len().min(200);
                result.context = Some(extract_context_bytes(&data, 0, context_len, 0));
            }
        } else if !text.is_empty() {
            let ctx_bytes = rules.context_bytes(&finding.rule_name).unwrap_or(200);
            if let Some((start, end)) = rules
                .matcher(&finding.rule_name)
                .and_then(|m| m.find_match(&text))
            {
                result.context = Some(extract_context(&text, start, end, ctx_bytes));
            } else {
                let context_len = text.len().min(200);
                result.context = Some(extract_context(&text, 0, context_len, 0));
            }
        }
        results.push(result);
    }

    // 6. Key inspection (always, even for binary)
    if let Some(key_finding) = inspect_key_material(&data) {
        let triage = if key_finding.is_encrypted {
            Triage::Red
        } else {
            Triage::Black
        };
        results.push(ResultMsg {
            timestamp: Utc::now(),
            host: msg.host.clone(),
            export_path: msg.export_path.clone(),
            file_path: msg.file_path.clone(),
            triage,
            rule_name: "KeyMaterial".into(),
            matched_pattern: key_finding.key_type.clone(),
            context: Some(format!(
                "{} (encrypted: {})",
                key_finding.key_type, key_finding.is_encrypted
            )),
            file_size: msg.attrs.size,
            file_mode: msg.attrs.mode,
            file_uid: msg.attrs.uid,
            file_gid: msg.attrs.gid,
            last_modified: DateTime::from_timestamp(msg.attrs.mtime.min(i64::MAX as u64) as i64, 0)
                .unwrap_or_default(),
        });
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::{
        ClassifierRule, EnumerationScope, MatchAction, MatchLocation, MatchType,
    };
    use crate::nfs::connector::MockNfsConnector;
    use crate::nfs::ops::MockNfsOps;
    use crate::nfs::{NfsError, NfsFileType, ReadResult};
    use chrono::Datelike;
    use std::path::PathBuf;

    fn mock_ops_success(data: Vec<u8>) -> MockNfsOps {
        let mut mock = MockNfsOps::new();
        mock.expect_read().returning(move |_, _, _| {
            Ok(ReadResult {
                data: data.clone(),
                eof: true,
            })
        });
        mock
    }

    fn mock_ops_permission_denied() -> MockNfsOps {
        let mut mock = MockNfsOps::new();
        mock.expect_read().returning(|_, _, _| {
            Err(Box::new(NfsError::PermissionDenied) as Box<dyn std::error::Error + Send + Sync>)
        });
        mock
    }

    fn test_attrs(uid: u32, gid: u32) -> NfsAttrs {
        NfsAttrs {
            file_type: NfsFileType::Regular,
            size: 1000,
            mode: 0o644,
            uid,
            gid,
            mtime: 0,
        }
    }

    fn test_auth_strategy(auto_cycle: bool, harvested: Vec<AuthCreds>) -> AuthStrategy {
        AuthStrategy {
            primary: AuthCreds::root(),
            harvested,
            auto_cycle,
            max_attempts: 5,
        }
    }

    #[tokio::test]
    async fn uid_cycling_primary_succeeds_no_cycling() {
        let mut connector = MockNfsConnector::new();
        connector
            .expect_connect()
            .times(1)
            .returning(|_, _, _| Ok(Box::new(mock_ops_success(b"data".to_vec()))));

        let mut cache = ConnectionCache::new();
        let fh = NfsFh::default();
        let attrs = test_attrs(1000, 1000);
        let auth = test_auth_strategy(true, vec![]);

        let result = read_with_uid_cycling(
            &connector, "h", "/e", &fh, &attrs, &auth, &mut cache, 1_048_576,
        )
        .await
        .unwrap();
        assert_eq!(result, b"data");
    }

    #[tokio::test]
    async fn uid_cycling_primary_fails_owner_succeeds() {
        let mut connector = MockNfsConnector::new();
        connector
            .expect_connect()
            .times(2)
            .returning(|_, _, creds| {
                if creds.uid == 0 {
                    Ok(Box::new(mock_ops_permission_denied()))
                } else {
                    Ok(Box::new(mock_ops_success(b"secret".to_vec())))
                }
            });

        let mut cache = ConnectionCache::new();
        let fh = NfsFh::default();
        let attrs = test_attrs(1000, 1000);
        let auth = test_auth_strategy(true, vec![]);

        let result = read_with_uid_cycling(
            &connector, "h", "/e", &fh, &attrs, &auth, &mut cache, 1_048_576,
        )
        .await
        .unwrap();
        assert_eq!(result, b"secret");
    }

    #[tokio::test]
    async fn uid_cycling_primary_and_owner_fail_harvested_succeeds() {
        let mut connector = MockNfsConnector::new();
        connector
            .expect_connect()
            .times(3)
            .returning(|_, _, creds| {
                if creds.uid == 2000 {
                    Ok(Box::new(mock_ops_success(b"found".to_vec())))
                } else {
                    Ok(Box::new(mock_ops_permission_denied()))
                }
            });

        let mut cache = ConnectionCache::new();
        let fh = NfsFh::default();
        let attrs = test_attrs(1000, 1000);
        let auth = test_auth_strategy(true, vec![AuthCreds::new(2000, 2000)]);

        let result = read_with_uid_cycling(
            &connector, "h", "/e", &fh, &attrs, &auth, &mut cache, 1_048_576,
        )
        .await
        .unwrap();
        assert_eq!(result, b"found");
    }

    #[tokio::test]
    async fn uid_cycling_all_fail_returns_error() {
        let mut connector = MockNfsConnector::new();
        connector
            .expect_connect()
            .returning(|_, _, _| Ok(Box::new(mock_ops_permission_denied())));

        let mut cache = ConnectionCache::new();
        let fh = NfsFh::default();
        let attrs = test_attrs(1000, 1000);
        let auth = test_auth_strategy(true, vec![AuthCreds::new(2000, 2000)]);

        let err = read_with_uid_cycling(
            &connector, "h", "/e", &fh, &attrs, &auth, &mut cache, 1_048_576,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ScannerError::AllUidsFailed(_)));
    }

    #[tokio::test]
    async fn uid_cycling_non_permission_error_propagates_immediately() {
        let mut connector = MockNfsConnector::new();
        connector.expect_connect().times(1).returning(|_, _, _| {
            let mut mock = MockNfsOps::new();
            mock.expect_read().returning(|_, _, _| {
                Err(Box::new(NfsError::StaleHandle) as Box<dyn std::error::Error + Send + Sync>)
            });
            Ok(Box::new(mock))
        });

        let mut cache = ConnectionCache::new();
        let fh = NfsFh::default();
        let attrs = test_attrs(1000, 1000);
        let auth = test_auth_strategy(true, vec![AuthCreds::new(2000, 2000)]);

        let err = read_with_uid_cycling(
            &connector, "h", "/e", &fh, &attrs, &auth, &mut cache, 1_048_576,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ScannerError::Nfs(NfsError::StaleHandle)));
    }

    #[tokio::test]
    async fn uid_cycling_disabled_no_cycling() {
        let mut connector = MockNfsConnector::new();
        connector
            .expect_connect()
            .times(1)
            .returning(|_, _, _| Ok(Box::new(mock_ops_permission_denied())));

        let mut cache = ConnectionCache::new();
        let fh = NfsFh::default();
        let attrs = test_attrs(1000, 1000);
        let auth = test_auth_strategy(false, vec![]);

        let err = read_with_uid_cycling(
            &connector, "h", "/e", &fh, &attrs, &auth, &mut cache, 1_048_576,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ScannerError::Nfs(NfsError::PermissionDenied)));
    }

    #[tokio::test]
    async fn uid_cycling_owner_same_as_primary_skips() {
        let mut connector = MockNfsConnector::new();
        connector
            .expect_connect()
            .times(2)
            .returning(|_, _, creds| {
                if creds.uid == 2000 {
                    Ok(Box::new(mock_ops_success(b"ok".to_vec())))
                } else {
                    Ok(Box::new(mock_ops_permission_denied()))
                }
            });

        let mut cache = ConnectionCache::new();
        let fh = NfsFh::default();
        let attrs = test_attrs(0, 0); // owner == primary (root)
        let auth = test_auth_strategy(true, vec![AuthCreds::new(2000, 2000)]);

        let result = read_with_uid_cycling(
            &connector, "h", "/e", &fh, &attrs, &auth, &mut cache, 1_048_576,
        )
        .await
        .unwrap();
        assert_eq!(result, b"ok");
    }

    #[tokio::test]
    async fn uid_cycling_harvested_skips_duplicates() {
        let mut connector = MockNfsConnector::new();
        connector
            .expect_connect()
            .times(3)
            .returning(|_, _, creds| {
                if creds.uid == 3000 {
                    Ok(Box::new(mock_ops_success(b"ok".to_vec())))
                } else {
                    Ok(Box::new(mock_ops_permission_denied()))
                }
            });

        let mut cache = ConnectionCache::new();
        let fh = NfsFh::default();
        let attrs = test_attrs(1000, 1000);
        // Harvested includes duplicates of primary (root) and owner (uid=1000)
        let auth = test_auth_strategy(
            true,
            vec![
                AuthCreds::root(),
                AuthCreds::new(1000, 1000),
                AuthCreds::new(3000, 3000),
            ],
        );

        let result = read_with_uid_cycling(
            &connector, "h", "/e", &fh, &attrs, &auth, &mut cache, 1_048_576,
        )
        .await
        .unwrap();
        assert_eq!(result, b"ok");
    }

    #[tokio::test]
    async fn uid_cycling_respects_max_attempts() {
        let mut connector = MockNfsConnector::new();
        // primary(0) + owner(1000) + 2 harvested from take(2) = 4 connections
        connector
            .expect_connect()
            .times(4)
            .returning(|_, _, _| Ok(Box::new(mock_ops_permission_denied())));

        let mut cache = ConnectionCache::new();
        let fh = NfsFh::default();
        let attrs = test_attrs(1000, 1000);
        let mut auth = test_auth_strategy(
            true,
            vec![
                AuthCreds::new(2000, 2000),
                AuthCreds::new(3000, 3000),
                AuthCreds::new(4000, 4000),
                AuthCreds::new(5000, 5000),
                AuthCreds::new(6000, 6000),
            ],
        );
        auth.max_attempts = 2;

        let err = read_with_uid_cycling(
            &connector, "h", "/e", &fh, &attrs, &auth, &mut cache, 1_048_576,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ScannerError::AllUidsFailed(_)));
    }

    #[tokio::test]
    async fn uid_cycling_max_attempts_counts_unique_tries_not_list_items() {
        let mut connector = MockNfsConnector::new();
        connector.expect_connect().returning(|_, _, creds| {
            if creds.uid == 5000 {
                Ok(Box::new(mock_ops_success(b"found".to_vec())))
            } else {
                Ok(Box::new(mock_ops_permission_denied()))
            }
        });

        let mut cache = ConnectionCache::new();
        let fh = NfsFh::default();
        let attrs = test_attrs(1000, 1000);
        // Harvested list has duplicates of primary (root=0) and owner (1000)
        // before the actual unique UID (5000).
        // With max_attempts=2, old code .take(2) consumes the two dups and never tries 5000.
        let mut auth = test_auth_strategy(
            true,
            vec![
                AuthCreds::root(),
                AuthCreds::new(1000, 1000),
                AuthCreds::new(5000, 5000),
            ],
        );
        auth.max_attempts = 2;

        let result = read_with_uid_cycling(
            &connector, "h", "/e", &fh, &attrs, &auth, &mut cache, 1_048_576,
        )
        .await;

        assert!(
            result.is_ok(),
            "uid=5000 should be reached despite max_attempts=2 because skipped dups don't count"
        );
        assert_eq!(result.unwrap(), b"found");
    }

    #[tokio::test]
    async fn uid_cycling_uses_connection_cache() {
        let mut connector = MockNfsConnector::new();
        connector
            .expect_connect()
            .times(1)
            .returning(|_, _, _| Ok(Box::new(mock_ops_success(b"cached".to_vec()))));

        let mut cache = ConnectionCache::new();
        let fh = NfsFh::default();
        let attrs = test_attrs(1000, 1000);
        let auth = test_auth_strategy(true, vec![]);

        let r1 = read_with_uid_cycling(
            &connector, "h", "/e", &fh, &attrs, &auth, &mut cache, 1_048_576,
        )
        .await
        .unwrap();
        let r2 = read_with_uid_cycling(
            &connector, "h", "/e", &fh, &attrs, &auth, &mut cache, 1_048_576,
        )
        .await
        .unwrap();
        assert_eq!(r1, b"cached");
        assert_eq!(r2, b"cached");
    }

    fn test_file_msg(name: &str) -> FileMsg {
        FileMsg {
            host: "testhost".into(),
            export_path: "/data".into(),
            file_path: format!("secrets/{name}"),
            file_handle: NfsFh::default(),
            attrs: NfsAttrs {
                file_type: NfsFileType::Regular,
                size: 1000,
                mode: 0o644,
                uid: 1000,
                gid: 1000,
                mtime: 1700000000,
            },
            reader: FileReader::Nfs {
                host: "testhost".into(),
                export: "/data".into(),
            },
            harvested_uids: vec![],
        }
    }

    fn test_file_msg_local(name: &str, path: PathBuf) -> FileMsg {
        FileMsg {
            host: "local".into(),
            export_path: "".into(),
            file_path: name.to_string(),
            file_handle: NfsFh::default(),
            attrs: NfsAttrs {
                file_type: NfsFileType::Regular,
                size: 1000,
                mode: 0o644,
                uid: 1000,
                gid: 1000,
                mtime: 1700000000,
            },
            reader: FileReader::Local { path },
            harvested_uids: vec![],
        }
    }

    fn make_file_rule(
        name: &str,
        location: MatchLocation,
        match_type: MatchType,
        patterns: Vec<&str>,
        action: MatchAction,
        triage: Option<Triage>,
    ) -> ClassifierRule {
        ClassifierRule {
            name: name.into(),
            scope: EnumerationScope::FileEnumeration,
            match_location: location,
            match_type,
            patterns: patterns.into_iter().map(String::from).collect(),
            action,
            triage,
            relay_targets: None,
            max_size: None,
            context_bytes: None,
            description: None,
        }
    }

    fn make_content_rule(
        name: &str,
        match_type: MatchType,
        patterns: Vec<&str>,
        triage: Option<Triage>,
    ) -> ClassifierRule {
        ClassifierRule {
            name: name.into(),
            scope: EnumerationScope::ContentsEnumeration,
            match_location: MatchLocation::FileContentAsString,
            match_type,
            patterns: patterns.into_iter().map(String::from).collect(),
            action: MatchAction::Snaffle,
            triage,
            relay_targets: None,
            max_size: None,
            context_bytes: None,
            description: None,
        }
    }

    fn noop_connector() -> MockNfsConnector {
        MockNfsConnector::new()
    }

    #[tokio::test]
    async fn scan_file_name_rule_snaffle() {
        let rule = make_file_rule(
            "KeepIdRsa",
            MatchLocation::FileName,
            MatchType::Exact,
            vec!["id_rsa"],
            MatchAction::Snaffle,
            Some(Triage::Black),
        );
        let engine = RuleEngine::compile(vec![rule]).unwrap();
        let mut connector = MockNfsConnector::new();
        connector
            .expect_connect()
            .returning(|_, _, _| Ok(Box::new(mock_ops_success(b"not a key".to_vec()))));
        let auth = test_auth_strategy(true, vec![]);
        let stats = PipelineStats::default();
        let mut cache = ConnectionCache::new();
        let msg = test_file_msg("id_rsa");

        let results = scan_file(
            &msg,
            &engine,
            &connector,
            &auth,
            OperatingMode::Scan,
            1_048_576,
            &mut cache,
            &stats,
            &HostHealthRegistry::default(),
        )
        .await;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].triage, Triage::Black);
        assert_eq!(results[0].rule_name, "KeepIdRsa");
        assert_eq!(results[0].host, "testhost");
        assert_eq!(results[0].export_path, "/data");
        assert_eq!(results[0].file_uid, 1000);
        assert_eq!(results[0].file_mode, 0o644);
    }

    #[tokio::test]
    async fn scan_file_name_rule_discard() {
        let discard = make_file_rule(
            "DiscardJpg",
            MatchLocation::FileExtension,
            MatchType::Exact,
            vec!["jpg"],
            MatchAction::Discard,
            None,
        );
        let snaffle = make_file_rule(
            "KeepAll",
            MatchLocation::FileName,
            MatchType::Contains,
            vec!["photo"],
            MatchAction::Snaffle,
            Some(Triage::Green),
        );
        let engine = RuleEngine::compile(vec![discard, snaffle]).unwrap();
        let mut connector = MockNfsConnector::new();
        connector
            .expect_connect()
            .returning(|_, _, _| Ok(Box::new(mock_ops_success(b"photo data".to_vec()))));
        let auth = test_auth_strategy(true, vec![]);
        let stats = PipelineStats::default();
        let mut cache = ConnectionCache::new();
        let msg = test_file_msg("photo.jpg");

        let results = scan_file(
            &msg,
            &engine,
            &connector,
            &auth,
            OperatingMode::Scan,
            1_048_576,
            &mut cache,
            &stats,
            &HostHealthRegistry::default(),
        )
        .await;

        assert!(results.is_empty(), "discard should stop processing");
    }

    #[tokio::test]
    async fn scan_file_enum_mode_skips_content() {
        let relay_rule = ClassifierRule {
            name: "RelayEnv".into(),
            scope: EnumerationScope::FileEnumeration,
            match_location: MatchLocation::FileExtension,
            match_type: MatchType::Exact,
            patterns: vec!["env".into()],
            action: MatchAction::Relay,
            triage: None,
            relay_targets: Some(vec!["ContentCheck".into()]),
            max_size: None,
            context_bytes: None,
            description: None,
        };
        let content_rule = make_content_rule(
            "ContentCheck",
            MatchType::Contains,
            vec!["PASSWORD"],
            Some(Triage::Red),
        );
        let engine = RuleEngine::compile(vec![relay_rule, content_rule]).unwrap();
        let connector = noop_connector();
        let auth = test_auth_strategy(true, vec![]);
        let stats = PipelineStats::default();
        let mut cache = ConnectionCache::new();
        let msg = test_file_msg("config.env");

        let results = scan_file(
            &msg,
            &engine,
            &connector,
            &auth,
            OperatingMode::Enumerate,
            1_048_576,
            &mut cache,
            &stats,
            &HostHealthRegistry::default(),
        )
        .await;

        // Enumerate mode: no content read, no content findings
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn scan_file_content_rule_snaffle_with_context() {
        let relay_rule = ClassifierRule {
            name: "RelayEnv".into(),
            scope: EnumerationScope::FileEnumeration,
            match_location: MatchLocation::FileExtension,
            match_type: MatchType::Exact,
            patterns: vec!["env".into()],
            action: MatchAction::Relay,
            triage: None,
            relay_targets: Some(vec!["ContentPassword".into()]),
            max_size: None,
            context_bytes: None,
            description: None,
        };
        let content_rule = make_content_rule(
            "ContentPassword",
            MatchType::Contains,
            vec!["PASSWORD"],
            Some(Triage::Red),
        );
        let mut connector = MockNfsConnector::new();
        connector.expect_connect().returning(|_, _, _| {
            Ok(Box::new(mock_ops_success(
                b"[config]\nhost = localhost\nDB_PASSWORD=secret123\nport = 5432".to_vec(),
            )))
        });
        let auth = test_auth_strategy(true, vec![]);
        let stats = PipelineStats::default();
        let mut cache = ConnectionCache::new();
        let engine = RuleEngine::compile(vec![relay_rule, content_rule]).unwrap();
        let msg = test_file_msg("config.env");

        let results = scan_file(
            &msg,
            &engine,
            &connector,
            &auth,
            OperatingMode::Scan,
            1_048_576,
            &mut cache,
            &stats,
            &HostHealthRegistry::default(),
        )
        .await;

        assert!(!results.is_empty());
        let content_result = results.iter().find(|r| r.rule_name == "ContentPassword");
        assert!(content_result.is_some(), "should find content rule match");
        let r = content_result.unwrap();
        assert_eq!(r.triage, Triage::Red);
        assert!(r.context.is_some(), "content finding should have context");
        let ctx = r.context.as_ref().unwrap();
        assert!(
            ctx.contains("PASSWORD"),
            "context should contain matched text"
        );
        assert!(
            !ctx.starts_with("[config]") || ctx.contains("PASSWORD"),
            "context should center on match, not file beginning"
        );
    }

    #[tokio::test]
    async fn scan_file_binary_skips_text_rules() {
        let relay_rule = ClassifierRule {
            name: "RelayBin".into(),
            scope: EnumerationScope::FileEnumeration,
            match_location: MatchLocation::FileExtension,
            match_type: MatchType::Exact,
            patterns: vec!["bin".into()],
            action: MatchAction::Relay,
            triage: None,
            relay_targets: Some(vec!["TextContent".into()]),
            max_size: None,
            context_bytes: None,
            description: None,
        };
        let content_rule = make_content_rule(
            "TextContent",
            MatchType::Contains,
            vec!["secret"],
            Some(Triage::Red),
        );
        // Binary content with null bytes
        let mut binary_data = b"secret data here".to_vec();
        binary_data.insert(5, 0x00);
        let mut connector = MockNfsConnector::new();
        let data = binary_data.clone();
        connector
            .expect_connect()
            .returning(move |_, _, _| Ok(Box::new(mock_ops_success(data.clone()))));
        let auth = test_auth_strategy(true, vec![]);
        let stats = PipelineStats::default();
        let mut cache = ConnectionCache::new();
        let engine = RuleEngine::compile(vec![relay_rule, content_rule]).unwrap();
        let msg = test_file_msg("test.bin");

        let results = scan_file(
            &msg,
            &engine,
            &connector,
            &auth,
            OperatingMode::Scan,
            1_048_576,
            &mut cache,
            &stats,
            &HostHealthRegistry::default(),
        )
        .await;

        // Binary: FileContentAsString rules should not match
        let text_match = results.iter().find(|r| r.rule_name == "TextContent");
        assert!(
            text_match.is_none(),
            "text rules should skip binary content"
        );
        assert_eq!(
            stats.files_skipped_binary.load(Ordering::Relaxed),
            1,
            "binary stat should increment"
        );
    }

    #[tokio::test]
    async fn scan_file_check_for_keys_ssh() {
        let rule = make_file_rule(
            "KeepIdRsa",
            MatchLocation::FileName,
            MatchType::Exact,
            vec!["id_rsa"],
            MatchAction::Snaffle,
            Some(Triage::Yellow),
        );
        let key_data = crate::scanner::keys::tests::UNENCRYPTED_ED25519_KEY
            .as_bytes()
            .to_vec();
        let mut connector = MockNfsConnector::new();
        connector
            .expect_connect()
            .returning(move |_, _, _| Ok(Box::new(mock_ops_success(key_data.clone()))));
        let auth = test_auth_strategy(true, vec![]);
        let stats = PipelineStats::default();
        let mut cache = ConnectionCache::new();
        let engine = RuleEngine::compile(vec![rule]).unwrap();
        let msg = test_file_msg("id_rsa");

        let results = scan_file(
            &msg,
            &engine,
            &connector,
            &auth,
            OperatingMode::Scan,
            1_048_576,
            &mut cache,
            &stats,
            &HostHealthRegistry::default(),
        )
        .await;

        let key_result = results.iter().find(|r| r.rule_name == "KeyMaterial");
        assert!(key_result.is_some(), "should detect SSH key");
        assert_eq!(key_result.unwrap().triage, Triage::Black);
    }

    #[tokio::test]
    async fn scan_file_check_for_keys_encrypted() {
        let rule = make_file_rule(
            "KeepIdRsa",
            MatchLocation::FileName,
            MatchType::Exact,
            vec!["id_rsa"],
            MatchAction::Snaffle,
            Some(Triage::Yellow),
        );
        let key_data = crate::scanner::keys::tests::ENCRYPTED_ED25519_KEY
            .as_bytes()
            .to_vec();
        let mut connector = MockNfsConnector::new();
        connector
            .expect_connect()
            .returning(move |_, _, _| Ok(Box::new(mock_ops_success(key_data.clone()))));
        let auth = test_auth_strategy(true, vec![]);
        let stats = PipelineStats::default();
        let mut cache = ConnectionCache::new();
        let engine = RuleEngine::compile(vec![rule]).unwrap();
        let msg = test_file_msg("id_rsa");

        let results = scan_file(
            &msg,
            &engine,
            &connector,
            &auth,
            OperatingMode::Scan,
            1_048_576,
            &mut cache,
            &stats,
            &HostHealthRegistry::default(),
        )
        .await;

        let key_result = results.iter().find(|r| r.rule_name == "KeyMaterial");
        assert!(key_result.is_some(), "should detect encrypted SSH key");
        assert_eq!(key_result.unwrap().triage, Triage::Red);
    }

    #[tokio::test]
    async fn scan_file_read_permission_denied_uid_cycles() {
        let relay_rule = ClassifierRule {
            name: "RelayEnv".into(),
            scope: EnumerationScope::FileEnumeration,
            match_location: MatchLocation::FileExtension,
            match_type: MatchType::Exact,
            patterns: vec!["env".into()],
            action: MatchAction::Relay,
            triage: None,
            relay_targets: Some(vec!["ContentCheck".into()]),
            max_size: None,
            context_bytes: None,
            description: None,
        };
        let content_rule = make_content_rule(
            "ContentCheck",
            MatchType::Contains,
            vec!["SECRET"],
            Some(Triage::Red),
        );
        let mut connector = MockNfsConnector::new();
        connector.expect_connect().returning(|_, _, creds| {
            if creds.uid == 0 {
                Ok(Box::new(mock_ops_permission_denied()))
            } else {
                Ok(Box::new(mock_ops_success(b"MY_SECRET=value".to_vec())))
            }
        });
        let auth = test_auth_strategy(true, vec![]);
        let stats = PipelineStats::default();
        let mut cache = ConnectionCache::new();
        let engine = RuleEngine::compile(vec![relay_rule, content_rule]).unwrap();
        let msg = test_file_msg("config.env");

        let results = scan_file(
            &msg,
            &engine,
            &connector,
            &auth,
            OperatingMode::Scan,
            1_048_576,
            &mut cache,
            &stats,
            &HostHealthRegistry::default(),
        )
        .await;

        let content_result = results.iter().find(|r| r.rule_name == "ContentCheck");
        assert!(content_result.is_some(), "UID cycling should succeed");
    }

    #[tokio::test]
    async fn scan_file_all_reads_fail_skips_gracefully() {
        let rule = make_file_rule(
            "KeepEnv",
            MatchLocation::FileExtension,
            MatchType::Exact,
            vec!["env"],
            MatchAction::Snaffle,
            Some(Triage::Yellow),
        );
        let mut connector = MockNfsConnector::new();
        connector
            .expect_connect()
            .returning(|_, _, _| Ok(Box::new(mock_ops_permission_denied())));
        let auth = test_auth_strategy(true, vec![]);
        let stats = PipelineStats::default();
        let mut cache = ConnectionCache::new();
        let engine = RuleEngine::compile(vec![rule]).unwrap();
        let msg = test_file_msg("config.env");

        let results = scan_file(
            &msg,
            &engine,
            &connector,
            &auth,
            OperatingMode::Scan,
            1_048_576,
            &mut cache,
            &stats,
            &HostHealthRegistry::default(),
        )
        .await;

        // Should have filename findings but no panic
        assert_eq!(results.len(), 1); // filename snaffle
        assert_eq!(results[0].rule_name, "KeepEnv");
    }

    #[tokio::test]
    async fn scan_file_local_mode_reads_from_disk() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"API_KEY=secret_value").unwrap();
        tmp.flush().unwrap();

        let relay_rule = ClassifierRule {
            name: "RelayTxt".into(),
            scope: EnumerationScope::FileEnumeration,
            match_location: MatchLocation::FileExtension,
            match_type: MatchType::Exact,
            patterns: vec!["txt".into()],
            action: MatchAction::Relay,
            triage: None,
            relay_targets: Some(vec!["FindApiKey".into()]),
            max_size: None,
            context_bytes: None,
            description: None,
        };
        let content_rule = make_content_rule(
            "FindApiKey",
            MatchType::Contains,
            vec!["API_KEY"],
            Some(Triage::Red),
        );
        let engine = RuleEngine::compile(vec![relay_rule, content_rule]).unwrap();
        let connector = noop_connector();
        let auth = test_auth_strategy(true, vec![]);
        let stats = PipelineStats::default();
        let mut cache = ConnectionCache::new();
        let msg = test_file_msg_local("config.txt", tmp.path().to_path_buf());

        let results = scan_file(
            &msg,
            &engine,
            &connector,
            &auth,
            OperatingMode::Scan,
            1_048_576,
            &mut cache,
            &stats,
            &HostHealthRegistry::default(),
        )
        .await;

        let api_result = results.iter().find(|r| r.rule_name == "FindApiKey");
        assert!(api_result.is_some(), "local read should find API_KEY");
    }

    #[tokio::test]
    async fn scan_file_name_finding_not_duplicated_with_content() {
        let rule = make_file_rule(
            "KeepEnv",
            MatchLocation::FileExtension,
            MatchType::Exact,
            vec!["env"],
            MatchAction::Snaffle,
            Some(Triage::Yellow),
        );
        let mut connector = MockNfsConnector::new();
        connector
            .expect_connect()
            .returning(|_, _, _| Ok(Box::new(mock_ops_success(b"some content".to_vec()))));
        let auth = test_auth_strategy(true, vec![]);
        let stats = PipelineStats::default();
        let mut cache = ConnectionCache::new();
        let engine = RuleEngine::compile(vec![rule]).unwrap();
        let msg = test_file_msg("config.env");

        let results = scan_file(
            &msg,
            &engine,
            &connector,
            &auth,
            OperatingMode::Scan,
            1_048_576,
            &mut cache,
            &stats,
            &HostHealthRegistry::default(),
        )
        .await;

        let env_results: Vec<_> = results
            .iter()
            .filter(|r| r.rule_name == "KeepEnv")
            .collect();
        assert_eq!(
            env_results.len(),
            1,
            "name-only finding should not be duplicated when content is also scanned"
        );
    }

    #[tokio::test]
    async fn scan_file_increments_stats() {
        let relay_rule = ClassifierRule {
            name: "RelayTxt".into(),
            scope: EnumerationScope::FileEnumeration,
            match_location: MatchLocation::FileExtension,
            match_type: MatchType::Exact,
            patterns: vec!["txt".into()],
            action: MatchAction::Relay,
            triage: None,
            relay_targets: Some(vec!["FindWord".into()]),
            max_size: None,
            context_bytes: None,
            description: None,
        };
        let content_rule = make_content_rule(
            "FindWord",
            MatchType::Contains,
            vec!["hello"],
            Some(Triage::Green),
        );
        let content_data = b"hello world".to_vec();
        let content_len = content_data.len() as u64;
        let mut connector = MockNfsConnector::new();
        connector
            .expect_connect()
            .returning(move |_, _, _| Ok(Box::new(mock_ops_success(content_data.clone()))));
        let auth = test_auth_strategy(true, vec![]);
        let stats = PipelineStats::default();
        let mut cache = ConnectionCache::new();
        let engine = RuleEngine::compile(vec![relay_rule, content_rule]).unwrap();
        let msg = test_file_msg("data.txt");

        let _results = scan_file(
            &msg,
            &engine,
            &connector,
            &auth,
            OperatingMode::Scan,
            1_048_576,
            &mut cache,
            &stats,
            &HostHealthRegistry::default(),
        )
        .await;

        assert_eq!(stats.files_content_scanned.load(Ordering::Relaxed), 1);
        assert_eq!(stats.bytes_read.load(Ordering::Relaxed), content_len);
    }

    #[test]
    fn finding_to_result_handles_large_mtime() {
        let mut msg = test_file_msg("test.txt");
        msg.attrs.mtime = u64::MAX;
        let finding = Finding {
            triage: Triage::Green,
            rule_name: "Test".into(),
            matched_pattern: "test".into(),
            context: None,
        };
        let result = finding_to_result(&finding, &msg);
        // Should not panic; should use a reasonable fallback
        assert!(result.last_modified.year() >= 1970);
    }

    #[tokio::test]
    async fn scan_file_uses_harvested_uids_from_file_msg() {
        let relay_rule = ClassifierRule {
            name: "RelayEnv".into(),
            scope: EnumerationScope::FileEnumeration,
            match_location: MatchLocation::FileExtension,
            match_type: MatchType::Exact,
            patterns: vec!["env".into()],
            action: MatchAction::Relay,
            triage: None,
            relay_targets: Some(vec!["ContentCheck".into()]),
            max_size: None,
            context_bytes: None,
            description: None,
        };
        let content_rule = make_content_rule(
            "ContentCheck",
            MatchType::Contains,
            vec!["SECRET"],
            Some(Triage::Red),
        );
        let mut connector = MockNfsConnector::new();
        // uid 0 (root/primary) and uid 1000 (owner) both fail,
        // but uid 5000 (from harvested_uids on FileMsg) succeeds
        connector.expect_connect().returning(|_, _, creds| {
            if creds.uid == 5000 {
                Ok(Box::new(mock_ops_success(b"MY_SECRET=value".to_vec())))
            } else {
                Ok(Box::new(mock_ops_permission_denied()))
            }
        });
        let auth = test_auth_strategy(true, vec![]); // No harvested UIDs in AuthStrategy
        let stats = PipelineStats::default();
        let mut cache = ConnectionCache::new();
        let engine = RuleEngine::compile(vec![relay_rule, content_rule]).unwrap();
        let mut msg = test_file_msg("config.env");
        // Attach harvested UIDs to the FileMsg (simulating discovery → walker propagation)
        msg.harvested_uids = vec![AuthCreds::new(5000, 5000)];

        let results = scan_file(
            &msg,
            &engine,
            &connector,
            &auth,
            OperatingMode::Scan,
            1_048_576,
            &mut cache,
            &stats,
            &HostHealthRegistry::default(),
        )
        .await;

        let content_result = results.iter().find(|r| r.rule_name == "ContentCheck");
        assert!(
            content_result.is_some(),
            "harvested UIDs from FileMsg should enable reading the file"
        );
    }
}
