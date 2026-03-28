/// Errors from NFS protocol operations.
#[derive(Debug, thiserror::Error)]
pub enum NfsError {
    /// NFS3ERR_ACCES or NFS3ERR_PERM — permission denied.
    #[error("permission denied")]
    PermissionDenied,

    /// NFS3ERR_STALE or NFS3ERR_BADHANDLE — server no longer recognizes handle.
    #[error("stale file handle")]
    StaleHandle,

    /// NFS3ERR_NOENT — file was deleted between readdir and read (race condition).
    #[error("not found")]
    NotFound,

    /// NFS3ERR_JUKEBOX, NFS3ERR_IO, timeout — retryable.
    #[error("transient: {0}")]
    Transient(String),

    /// TCP reset, connection refused — connection is dead.
    #[error("connection lost")]
    ConnectionLost,

    /// Mount denied, NFS3ERR_SERVERFAULT — entire export is unusable.
    #[error("export fatal: {0}")]
    ExportFatal(String),
}

impl NfsError {
    /// Convenience check for UID cycling logic.
    pub fn is_permission_denied(&self) -> bool {
        matches!(self, Self::PermissionDenied)
    }
}

/// Coarse error classification for handling decisions.
#[derive(Debug, PartialEq, Eq)]
pub enum ErrorClass {
    PermissionDenied,
    Stale,
    NotFound,
    Transient,
    ConnectionLost,
    Fatal,
}

/// Classify an NFS error into a coarse category for handling decisions.
pub fn classify_error(e: &NfsError) -> ErrorClass {
    match e {
        NfsError::PermissionDenied => ErrorClass::PermissionDenied,
        NfsError::StaleHandle => ErrorClass::Stale,
        NfsError::NotFound => ErrorClass::NotFound,
        NfsError::Transient(_) => ErrorClass::Transient,
        NfsError::ConnectionLost => ErrorClass::ConnectionLost,
        NfsError::ExportFatal(_) => ErrorClass::Fatal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_permission_denied() {
        assert_eq!(
            classify_error(&NfsError::PermissionDenied),
            ErrorClass::PermissionDenied
        );
    }

    #[test]
    fn classify_stale_handle() {
        assert_eq!(classify_error(&NfsError::StaleHandle), ErrorClass::Stale);
    }

    #[test]
    fn classify_not_found() {
        assert_eq!(classify_error(&NfsError::NotFound), ErrorClass::NotFound);
    }

    #[test]
    fn classify_transient() {
        assert_eq!(
            classify_error(&NfsError::Transient("timeout".into())),
            ErrorClass::Transient
        );
    }

    #[test]
    fn classify_connection_lost() {
        assert_eq!(
            classify_error(&NfsError::ConnectionLost),
            ErrorClass::ConnectionLost
        );
    }

    #[test]
    fn classify_export_fatal() {
        assert_eq!(
            classify_error(&NfsError::ExportFatal("mount denied".into())),
            ErrorClass::Fatal
        );
    }

    #[test]
    fn is_permission_denied_helper() {
        assert!(NfsError::PermissionDenied.is_permission_denied());
        assert!(!NfsError::NotFound.is_permission_denied());
        assert!(!NfsError::StaleHandle.is_permission_denied());
        assert!(!NfsError::Transient("x".into()).is_permission_denied());
        assert!(!NfsError::ConnectionLost.is_permission_denied());
        assert!(!NfsError::ExportFatal("x".into()).is_permission_denied());
    }

    #[test]
    fn nfs_error_display() {
        assert_eq!(NfsError::PermissionDenied.to_string(), "permission denied");
        assert_eq!(NfsError::StaleHandle.to_string(), "stale file handle");
        assert_eq!(NfsError::NotFound.to_string(), "not found");
        assert_eq!(
            NfsError::Transient("timeout".into()).to_string(),
            "transient: timeout"
        );
        assert_eq!(NfsError::ConnectionLost.to_string(), "connection lost");
        assert_eq!(
            NfsError::ExportFatal("mount denied".into()).to_string(),
            "export fatal: mount denied"
        );
    }

    #[test]
    fn nfs_error_is_std_error() {
        let err: &dyn std::error::Error = &NfsError::PermissionDenied;
        assert!(!err.to_string().is_empty());
    }
}
