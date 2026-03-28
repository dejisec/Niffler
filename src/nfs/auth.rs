/// Credentials for NFS AUTH_SYS authentication.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthCreds {
    pub uid: u32,
    pub gid: u32,
    pub aux_gids: Vec<u32>,
}

impl AuthCreds {
    pub fn root() -> Self {
        Self {
            uid: 0,
            gid: 0,
            aux_gids: vec![0],
        }
    }

    pub fn nobody() -> Self {
        Self {
            uid: 65534,
            gid: 65534,
            aux_gids: vec![],
        }
    }

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
    use std::collections::HashMap;

    #[test]
    fn auth_creds_root_returns_uid_0_gid_0() {
        let creds = AuthCreds::root();
        assert_eq!(creds.uid, 0);
        assert_eq!(creds.gid, 0);
        assert!(creds.aux_gids.contains(&0));
    }

    #[test]
    fn auth_creds_nobody_returns_65534() {
        let creds = AuthCreds::nobody();
        assert_eq!(creds.uid, 65534);
        assert_eq!(creds.gid, 65534);
        assert!(creds.aux_gids.is_empty());
    }

    #[test]
    fn auth_creds_new_sets_aux_gids() {
        let creds = AuthCreds::new(1000, 1000);
        assert_eq!(creds.uid, 1000);
        assert_eq!(creds.gid, 1000);
        assert_eq!(creds.aux_gids, vec![1000]);
    }

    #[test]
    fn auth_creds_root_equals_root() {
        assert_eq!(AuthCreds::root(), AuthCreds::root());
    }

    #[test]
    fn auth_creds_root_not_equal_nobody() {
        assert_ne!(AuthCreds::root(), AuthCreds::nobody());
    }

    #[test]
    fn auth_creds_usable_as_hashmap_key() {
        let mut map = HashMap::new();
        map.insert(AuthCreds::root(), "root");
        map.insert(AuthCreds::nobody(), "nobody");

        assert_eq!(map.get(&AuthCreds::root()), Some(&"root"));
        assert_eq!(map.get(&AuthCreds::nobody()), Some(&"nobody"));
    }

    #[test]
    fn auth_strategy_default_construction() {
        let strategy = AuthStrategy::new(AuthCreds::root());
        assert_eq!(strategy.primary, AuthCreds::root());
        assert!(strategy.harvested.is_empty());
        assert!(strategy.auto_cycle);
        assert_eq!(strategy.max_attempts, 5);
    }
}
