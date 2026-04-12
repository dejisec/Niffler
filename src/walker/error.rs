use tokio::sync::mpsc::error::SendError;

use crate::nfs::{ErrorClass, NfsError, classify_error};
use crate::pipeline::FileMsg;

#[derive(Debug, thiserror::Error)]
pub enum WalkerError {
    #[error("NFS error: {0}")]
    Nfs(#[from] NfsError),

    #[error("walker channel closed")]
    ChannelClosed,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("NFS operation timed out: {0}")]
    Timeout(String),
}

impl From<SendError<FileMsg>> for WalkerError {
    fn from(_: SendError<FileMsg>) -> Self {
        Self::ChannelClosed
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for WalkerError {
    fn from(err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        match err.downcast::<NfsError>() {
            Ok(nfs_err) => Self::Nfs(*nfs_err),
            Err(other) => Self::Io(std::io::Error::other(other.to_string())),
        }
    }
}

impl WalkerError {
    #[must_use]
    pub fn classify(&self) -> ErrorClass {
        match self {
            Self::Nfs(e) => classify_error(e),
            Self::ChannelClosed => ErrorClass::Fatal,
            Self::Io(_) => ErrorClass::Transient,
            Self::Timeout(_) => ErrorClass::Transient,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walker_error_from_nfs_permission_denied() {
        let err = WalkerError::from(NfsError::PermissionDenied);
        assert!(matches!(err, WalkerError::Nfs(NfsError::PermissionDenied)));
    }

    #[test]
    fn walker_error_from_nfs_stale_handle() {
        let err = WalkerError::from(NfsError::StaleHandle);
        assert!(matches!(err, WalkerError::Nfs(NfsError::StaleHandle)));
    }

    #[test]
    fn walker_error_from_nfs_connection_lost() {
        let err = WalkerError::from(NfsError::ConnectionLost);
        assert!(matches!(err, WalkerError::Nfs(NfsError::ConnectionLost)));
    }

    #[test]
    fn walker_error_channel_closed_display() {
        let err = WalkerError::ChannelClosed;
        let msg = err.to_string().to_lowercase();
        assert!(msg.contains("channel"));
    }

    #[test]
    fn walker_error_io_from_std() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "test");
        let err = WalkerError::from(io_err);
        assert!(matches!(err, WalkerError::Io(_)));
    }

    #[test]
    fn walker_error_classify_nfs_delegates() {
        let perm = WalkerError::Nfs(NfsError::PermissionDenied);
        assert_eq!(perm.classify(), ErrorClass::PermissionDenied);

        let stale = WalkerError::Nfs(NfsError::StaleHandle);
        assert_eq!(stale.classify(), ErrorClass::Stale);

        let conn = WalkerError::Nfs(NfsError::ConnectionLost);
        assert_eq!(conn.classify(), ErrorClass::ConnectionLost);
    }

    #[test]
    fn walker_error_classify_non_nfs_is_fatal() {
        assert_eq!(WalkerError::ChannelClosed.classify(), ErrorClass::Fatal);
    }
}
