use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::classifier::Triage;
use crate::nfs::{AuthCreds, ExportAccessOptions, Misconfiguration, NfsAttrs, NfsFh, NfsVersion};

/// Discovery → Walker: one discovered NFS export to walk.
#[derive(Debug, Clone)]
pub struct ExportMsg {
    pub host: String,
    pub export_path: String,
    pub nfs_version: NfsVersion,
    pub access_options: ExportAccessOptions,
    pub harvested_uids: Vec<AuthCreds>,
    pub misconfigs: Vec<Misconfiguration>,
}

/// How to read file content — NFS remote or local filesystem.
#[derive(Debug, Clone)]
pub enum FileReader {
    Nfs { host: String, export: String },
    Local { path: PathBuf },
}

/// Walker → Scanner: one file to scan.
#[derive(Debug)]
pub struct FileMsg {
    pub host: String,
    pub export_path: String,
    pub file_path: String,
    pub file_handle: NfsFh,
    pub attrs: NfsAttrs,
    pub reader: FileReader,
    /// UID/GID pairs harvested during discovery for this export.
    pub harvested_uids: Vec<AuthCreds>,
}

/// Scanner → Output: one finding to report.
#[derive(Debug, Serialize)]
pub struct ResultMsg {
    pub timestamp: DateTime<Utc>,
    pub host: String,
    pub export_path: String,
    pub file_path: String,
    pub triage: Triage,
    pub rule_name: String,
    pub matched_pattern: String,
    pub context: Option<String>,
    pub file_size: u64,
    pub file_mode: u32,
    pub file_uid: u32,
    pub file_gid: u32,
    pub last_modified: DateTime<Utc>,
}

/// Owns all sender/receiver pairs for the three pipeline channels.
/// Destructured during pipeline setup: senders cloned into tasks, receivers moved.
pub struct PipelineChannels {
    pub export_tx: Sender<ExportMsg>,
    pub export_rx: Receiver<ExportMsg>,
    pub file_tx: Sender<FileMsg>,
    pub file_rx: Receiver<FileMsg>,
    pub result_tx: Sender<ResultMsg>,
    pub result_rx: Receiver<ResultMsg>,
}

pub const DEFAULT_EXPORT_CHANNEL_BOUND: usize = 5000;
pub const DEFAULT_FILE_CHANNEL_BOUND: usize = 50000;
pub const DEFAULT_RESULT_CHANNEL_BOUND: usize = 10000;

impl PipelineChannels {
    #[must_use]
    pub fn new(export_bound: usize, file_bound: usize, result_bound: usize) -> Self {
        let export_bound = export_bound.max(1);
        let file_bound = file_bound.max(1);
        let result_bound = result_bound.max(1);
        let (export_tx, export_rx) = tokio::sync::mpsc::channel(export_bound);
        let (file_tx, file_rx) = tokio::sync::mpsc::channel(file_bound);
        let (result_tx, result_rx) = tokio::sync::mpsc::channel(result_bound);
        Self {
            export_tx,
            export_rx,
            file_tx,
            file_rx,
            result_tx,
            result_rx,
        }
    }
}

impl Default for PipelineChannels {
    fn default() -> Self {
        Self::new(
            DEFAULT_EXPORT_CHANNEL_BOUND,
            DEFAULT_FILE_CHANNEL_BOUND,
            DEFAULT_RESULT_CHANNEL_BOUND,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::nfs::{ExportAccessOptions, NfsVersion};
    use tokio::sync::mpsc::error::TrySendError;

    fn make_export_msg(host: &str) -> ExportMsg {
        ExportMsg {
            host: host.into(),
            export_path: "/data".into(),
            nfs_version: NfsVersion::V3,
            access_options: ExportAccessOptions::default(),
            harvested_uids: vec![],
            misconfigs: vec![],
        }
    }

    #[tokio::test]
    async fn bounded_channel_rejects_when_full() {
        let mut channels = PipelineChannels::new(2, 2, 2);

        channels.export_tx.try_send(make_export_msg("h1")).unwrap();
        channels.export_tx.try_send(make_export_msg("h2")).unwrap();

        let err = channels
            .export_tx
            .try_send(make_export_msg("h3"))
            .unwrap_err();
        assert!(matches!(err, TrySendError::Full(_)));

        let received = channels.export_rx.recv().await.unwrap();
        assert_eq!(received.host, "h1");

        channels.export_tx.try_send(make_export_msg("h3")).unwrap();
    }

    #[tokio::test]
    async fn send_blocks_until_receiver_drains() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<ExportMsg>(1);

        // Fill the single slot.
        tx.send(make_export_msg("first")).await.unwrap();

        // Spawn a task that drains after a brief delay, then receives the second message too.
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let first = rx.recv().await.unwrap();
            let second = rx.recv().await.unwrap();
            (first, second)
        });

        // This send blocks until the spawned task receives "first", freeing the slot.
        let result = tokio::time::timeout(Duration::from_secs(2), async {
            tx.send(make_export_msg("second")).await.unwrap();
        })
        .await;
        assert!(result.is_ok(), "send should unblock once receiver drains");

        let (first, second) = handle.await.unwrap();
        assert_eq!(first.host, "first");
        assert_eq!(second.host, "second");
    }
}
