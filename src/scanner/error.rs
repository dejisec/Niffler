use tokio::sync::mpsc::error::SendError;

use crate::nfs::{ErrorClass, NfsError, NfsFh, classify_error};
use crate::pipeline::ResultMsg;

#[derive(Debug, thiserror::Error)]
pub enum ScannerError {
    #[error("NFS error: {0}")]
    Nfs(#[from] NfsError),

    #[error("all UIDs failed for file handle {0:?}")]
    AllUidsFailed(NfsFh),

    #[error("read error: {0}")]
    ReadError(String),

    #[error("scanner channel closed")]
    ChannelClosed,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<SendError<ResultMsg>> for ScannerError {
    fn from(_: SendError<ResultMsg>) -> Self {
        Self::ChannelClosed
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for ScannerError {
    fn from(err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        match err.downcast::<NfsError>() {
            Ok(nfs_err) => Self::Nfs(*nfs_err),
            Err(other) => Self::Io(std::io::Error::other(other.to_string())),
        }
    }
}

impl ScannerError {
    pub fn classify(&self) -> ErrorClass {
        match self {
            Self::Nfs(e) => classify_error(e),
            Self::AllUidsFailed(_) => ErrorClass::PermissionDenied,
            Self::ReadError(_) => ErrorClass::Transient,
            Self::ChannelClosed => ErrorClass::Fatal,
            Self::Io(_) => ErrorClass::Transient,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanner_error_from_nfs_permission_denied() {
        let err = ScannerError::from(NfsError::PermissionDenied);
        assert!(matches!(err, ScannerError::Nfs(NfsError::PermissionDenied)));
    }

    #[test]
    fn scanner_error_from_nfs_stale_handle() {
        let err = ScannerError::from(NfsError::StaleHandle);
        assert!(matches!(err, ScannerError::Nfs(NfsError::StaleHandle)));
    }

    #[test]
    fn scanner_error_from_nfs_connection_lost() {
        let err = ScannerError::from(NfsError::ConnectionLost);
        assert!(matches!(err, ScannerError::Nfs(NfsError::ConnectionLost)));
    }

    #[test]
    fn scanner_error_all_uids_failed_display() {
        let err = ScannerError::AllUidsFailed(NfsFh::default());
        let msg = err.to_string().to_lowercase();
        assert!(msg.contains("uid"));
    }

    #[test]
    fn scanner_error_channel_closed_display() {
        let err = ScannerError::ChannelClosed;
        let msg = err.to_string().to_lowercase();
        assert!(msg.contains("channel"));
    }

    #[test]
    fn scanner_error_io_from_std() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "test");
        let err = ScannerError::from(io_err);
        assert!(matches!(err, ScannerError::Io(_)));
    }

    #[test]
    fn scanner_error_classify_nfs_delegates() {
        let perm = ScannerError::Nfs(NfsError::PermissionDenied);
        assert_eq!(perm.classify(), ErrorClass::PermissionDenied);

        let stale = ScannerError::Nfs(NfsError::StaleHandle);
        assert_eq!(stale.classify(), ErrorClass::Stale);

        let conn = ScannerError::Nfs(NfsError::ConnectionLost);
        assert_eq!(conn.classify(), ErrorClass::ConnectionLost);
    }

    #[test]
    fn scanner_error_classify_non_nfs_is_fatal() {
        assert_eq!(ScannerError::ChannelClosed.classify(), ErrorClass::Fatal);
        assert_eq!(
            ScannerError::AllUidsFailed(NfsFh::default()).classify(),
            ErrorClass::PermissionDenied
        );
    }
}
