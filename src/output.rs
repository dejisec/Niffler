pub mod console;
pub mod json;
pub mod tsv;
pub mod types;

pub use types::DeduplicationKey;
pub use types::file_mode_to_rwx;

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufWriter, Write};

use anyhow::Result;
use tokio::sync::mpsc;

use crate::config::{OutputConfig, OutputFormat};
use crate::pipeline::ResultMsg;

/// Async output sink — reads `ResultMsg` from the pipeline channel and routes
/// each finding to the configured formatter, flushing after every write.
pub async fn run(mut rx: mpsc::Receiver<ResultMsg>, config: &OutputConfig) -> Result<()> {
    let mut writer: Box<dyn Write + Send> = match &config.output_file {
        Some(path) => Box::new(BufWriter::new(File::create(path)?)),
        None => Box::new(std::io::stdout()),
    };

    let mut seen = HashSet::new();

    while let Some(msg) = rx.recv().await {
        if msg.triage < config.min_severity {
            continue;
        }

        let key = DeduplicationKey::from_result(&msg);
        if !seen.insert(key) {
            tracing::debug!(
                host = %msg.host,
                export = %msg.export_path,
                file = %msg.file_path,
                rule = %msg.rule_name,
                "suppressed duplicate finding"
            );
            continue;
        }

        match config.format {
            OutputFormat::Console => console::write_console(&msg, &mut *writer)?,
            OutputFormat::Json => json::write_json(&msg, &mut *writer)?,
            OutputFormat::Tsv => tsv::write_tsv(&msg, &mut *writer)?,
        }
        writer.flush()?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::Triage;
    use chrono::Utc;
    use tempfile::NamedTempFile;

    fn make_msg(triage: Triage, context: Option<String>) -> ResultMsg {
        ResultMsg {
            timestamp: Utc::now(),
            host: "nfs-server".into(),
            export_path: "/exports/home".into(),
            file_path: "user1/.ssh/id_rsa".into(),
            triage,
            rule_name: "SSHPrivateKey".into(),
            matched_pattern: "id_rsa".into(),
            context,
            file_size: 1700,
            file_mode: 0o644,
            file_uid: 1001,
            file_gid: 1001,
            last_modified: Utc::now(),
        }
    }

    #[tokio::test]
    async fn dispatcher_routes_json_to_file() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let (tx, rx) = mpsc::channel::<ResultMsg>(10);

        tx.send(make_msg(Triage::Black, Some("secret".into())))
            .await
            .unwrap();
        drop(tx);

        let config = OutputConfig {
            format: OutputFormat::Json,
            output_file: Some(path.clone()),
            min_severity: Triage::Green,
        };
        run(rx, &config).await.unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(contents.trim());
        assert!(parsed.is_ok(), "output should be valid JSON: {contents}");
    }

    #[tokio::test]
    async fn dispatcher_routes_tsv_to_file() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let (tx, rx) = mpsc::channel::<ResultMsg>(10);

        tx.send(make_msg(Triage::Red, None)).await.unwrap();
        drop(tx);

        let config = OutputConfig {
            format: OutputFormat::Tsv,
            output_file: Some(path.clone()),
            min_severity: Triage::Green,
        };
        run(rx, &config).await.unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(
            contents.contains('\t'),
            "TSV output should contain tabs: {contents}"
        );
    }

    #[tokio::test]
    async fn dispatcher_routes_console_to_file() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let (tx, rx) = mpsc::channel::<ResultMsg>(10);

        tx.send(make_msg(Triage::Black, None)).await.unwrap();
        drop(tx);

        let config = OutputConfig {
            format: OutputFormat::Console,
            output_file: Some(path.clone()),
            min_severity: Triage::Green,
        };
        run(rx, &config).await.unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(
            contents.contains("BLACK"),
            "console output should contain triage severity: {contents}"
        );
    }

    #[tokio::test]
    async fn dispatcher_handles_empty_channel() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let (_tx, rx) = mpsc::channel::<ResultMsg>(10);
        drop(_tx);

        let config = OutputConfig {
            format: OutputFormat::Json,
            output_file: Some(path),
            min_severity: Triage::Green,
        };
        let result = run(rx, &config).await;
        assert!(result.is_ok(), "empty channel should return Ok");
    }

    #[tokio::test]
    async fn dispatcher_multiple_findings() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let (tx, rx) = mpsc::channel::<ResultMsg>(10);

        // Use distinct rule_names so dedup doesn't suppress them
        let mut msg1 = make_msg(Triage::Black, Some("key1".into()));
        msg1.rule_name = "RuleA".into();
        let mut msg2 = make_msg(Triage::Red, Some("key2".into()));
        msg2.rule_name = "RuleB".into();
        let mut msg3 = make_msg(Triage::Green, None);
        msg3.rule_name = "RuleC".into();

        tx.send(msg1).await.unwrap();
        tx.send(msg2).await.unwrap();
        tx.send(msg3).await.unwrap();
        drop(tx);

        let config = OutputConfig {
            format: OutputFormat::Json,
            output_file: Some(path.clone()),
            min_severity: Triage::Green,
        };
        run(rx, &config).await.unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 3, "should have exactly 3 lines: {contents}");
        for (i, line) in lines.iter().enumerate() {
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
            assert!(parsed.is_ok(), "line {i} should be valid JSON: {line}");
        }
    }

    #[tokio::test]
    async fn dispatcher_filters_below_min_severity() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let (tx, rx) = mpsc::channel::<ResultMsg>(10);

        // Use distinct rule_names so dedup doesn't suppress them
        let mut msg1 = make_msg(Triage::Green, None);
        msg1.rule_name = "RuleA".into();
        let mut msg2 = make_msg(Triage::Yellow, None);
        msg2.rule_name = "RuleB".into();
        let mut msg3 = make_msg(Triage::Red, Some("cred".into()));
        msg3.rule_name = "RuleC".into();
        let mut msg4 = make_msg(Triage::Black, Some("key".into()));
        msg4.rule_name = "RuleD".into();

        tx.send(msg1).await.unwrap();
        tx.send(msg2).await.unwrap();
        tx.send(msg3).await.unwrap();
        tx.send(msg4).await.unwrap();
        drop(tx);

        let config = OutputConfig {
            format: OutputFormat::Json,
            output_file: Some(path.clone()),
            min_severity: Triage::Red,
        };
        run(rx, &config).await.unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(
            lines.len(),
            2,
            "only Red and Black should pass filter, got: {contents}"
        );
    }

    #[tokio::test]
    async fn dispatcher_deduplicates_identical_findings() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let (tx, rx) = mpsc::channel::<ResultMsg>(10);

        // Send two identical findings (same host/export/file/rule)
        tx.send(make_msg(Triage::Black, Some("secret".into())))
            .await
            .unwrap();
        tx.send(make_msg(Triage::Black, Some("secret".into())))
            .await
            .unwrap();
        drop(tx);

        let config = OutputConfig {
            format: OutputFormat::Json,
            output_file: Some(path.clone()),
            min_severity: Triage::Green,
        };
        run(rx, &config).await.unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(
            lines.len(),
            1,
            "duplicate finding should be suppressed: {contents}"
        );
    }

    #[tokio::test]
    async fn dispatcher_allows_different_rules_same_file() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let (tx, rx) = mpsc::channel::<ResultMsg>(10);

        let mut msg1 = make_msg(Triage::Black, Some("key".into()));
        msg1.rule_name = "RuleA".into();
        let mut msg2 = make_msg(Triage::Red, Some("cred".into()));
        msg2.rule_name = "RuleB".into();
        tx.send(msg1).await.unwrap();
        tx.send(msg2).await.unwrap();
        drop(tx);

        let config = OutputConfig {
            format: OutputFormat::Json,
            output_file: Some(path.clone()),
            min_severity: Triage::Green,
        };
        run(rx, &config).await.unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(
            lines.len(),
            2,
            "different rules on same file should both appear: {contents}"
        );
    }

    #[tokio::test]
    async fn dispatcher_allows_same_rule_different_files() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let (tx, rx) = mpsc::channel::<ResultMsg>(10);

        let mut msg1 = make_msg(Triage::Black, Some("key".into()));
        msg1.file_path = "user1/.ssh/id_rsa".into();
        let mut msg2 = make_msg(Triage::Black, Some("key".into()));
        msg2.file_path = "user2/.ssh/id_rsa".into();
        tx.send(msg1).await.unwrap();
        tx.send(msg2).await.unwrap();
        drop(tx);

        let config = OutputConfig {
            format: OutputFormat::Json,
            output_file: Some(path.clone()),
            min_severity: Triage::Green,
        };
        run(rx, &config).await.unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(
            lines.len(),
            2,
            "same rule on different files should both appear: {contents}"
        );
    }
}
