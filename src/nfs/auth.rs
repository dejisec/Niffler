/// Credentials for NFS AUTH_SYS authentication.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthCreds {
    pub uid: u32,
    pub gid: u32,
    pub aux_gids: Vec<u32>,
}

impl AuthCreds {
    #[must_use]
    pub fn root() -> Self {
        Self {
            uid: 0,
            gid: 0,
            aux_gids: vec![0],
        }
    }

    #[must_use]
    pub fn nobody() -> Self {
        Self {
            uid: 65534,
            gid: 65534,
            aux_gids: vec![],
        }
    }

    #[must_use]
    pub fn new(uid: u32, gid: u32) -> Self {
        Self {
            uid,
            gid,
            aux_gids: vec![gid],
        }
    }
}

/// Strategy for UID/GID cycling on permission denied.
#[derive(Debug, Clone)]
pub struct AuthStrategy {
    /// Primary credentials (from --uid/--gid flags or default root).
    pub primary: AuthCreds,
    /// UID/GID pairs harvested from stat() during discovery.
    pub harvested: Vec<AuthCreds>,
    /// Cycle through harvested UIDs on permission denied.
    pub auto_cycle: bool,
    /// Max UIDs to try before giving up on a file.
    pub max_attempts: usize,
}

impl AuthStrategy {
    #[must_use]
    pub fn new(primary: AuthCreds) -> Self {
        Self {
            primary,
            harvested: vec![],
            auto_cycle: true,
            max_attempts: 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_creds_new_sets_aux_gids() {
        let creds = AuthCreds::new(1000, 1000);
        assert_eq!(creds.uid, 1000);
        assert_eq!(creds.gid, 1000);
        assert_eq!(creds.aux_gids, vec![1000]);
    }
}
