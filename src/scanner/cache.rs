use std::collections::{HashMap, VecDeque};

use crate::nfs::{AuthCreds, NfsConnector, NfsOps};

use super::error::ScannerError;

type CacheKey = (String, String, u32, u32);

pub(crate) struct ConnectionCache {
    cache: HashMap<CacheKey, Box<dyn NfsOps>>,
    /// Tracks access order: front = LRU, back = most recently used.
    order: VecDeque<CacheKey>,
    max_entries: usize,
}

impl ConnectionCache {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            order: VecDeque::new(),
            max_entries: 256,
        }
    }

    #[cfg(test)]
    pub fn with_max_entries(max: usize) -> Self {
        Self {
            cache: HashMap::new(),
            order: VecDeque::new(),
            max_entries: max,
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    #[cfg(test)]
    pub fn contains_key(&self, host: &str, export: &str, creds: &AuthCreds) -> bool {
        let key = (host.to_string(), export.to_string(), creds.uid, creds.gid);
        self.cache.contains_key(&key)
    }

    /// Move `key` to the back of the LRU order (most recently used).
    fn touch(&mut self, key: &CacheKey) {
        if let Some(pos) = self.order.iter().position(|k| k == key) {
            self.order.remove(pos);
        }
        self.order.push_back(key.clone());
    }

    pub async fn get_or_connect(
        &mut self,
        connector: &dyn NfsConnector,
        host: &str,
        export: &str,
        creds: &AuthCreds,
    ) -> Result<&mut dyn NfsOps, ScannerError> {
        let key: CacheKey = (host.to_string(), export.to_string(), creds.uid, creds.gid);

        if self.cache.contains_key(&key) {
            self.touch(&key);
        } else {
            if self.cache.len() >= self.max_entries
                && let Some(evict_key) = self.order.pop_front()
            {
                self.cache.remove(&evict_key);
            }
            let ops = connector.connect(host, export, creds).await?;
            self.cache.insert(key.clone(), ops);
            self.order.push_back(key.clone());
        }

        Ok(&mut **self.cache.get_mut(&key).expect("key was inserted above"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs::NfsError;
    use crate::nfs::connector::MockNfsConnector;
    use crate::nfs::ops::MockNfsOps;

    #[tokio::test]
    async fn cache_miss_creates_connection() {
        let mut connector = MockNfsConnector::new();
        connector.expect_connect().times(1).returning(|_, _, _| {
            let mock = MockNfsOps::new();
            Ok(Box::new(mock))
        });

        let mut cache = ConnectionCache::new();
        let result = cache
            .get_or_connect(&connector, "host1", "/export", &AuthCreds::root())
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn cache_hit_reuses_connection() {
        let mut connector = MockNfsConnector::new();
        connector.expect_connect().times(1).returning(|_, _, _| {
            let mock = MockNfsOps::new();
            Ok(Box::new(mock))
        });

        let mut cache = ConnectionCache::new();
        let creds = AuthCreds::root();

        cache
            .get_or_connect(&connector, "host1", "/export", &creds)
            .await
            .unwrap();
        cache
            .get_or_connect(&connector, "host1", "/export", &creds)
            .await
            .unwrap();
        // MockNfsConnector enforces times(1) — second call reused cache
    }

    #[tokio::test]
    async fn different_creds_create_different_connections() {
        let mut connector = MockNfsConnector::new();
        connector.expect_connect().times(2).returning(|_, _, _| {
            let mock = MockNfsOps::new();
            Ok(Box::new(mock))
        });

        let mut cache = ConnectionCache::new();
        cache
            .get_or_connect(&connector, "host1", "/data", &AuthCreds::root())
            .await
            .unwrap();
        cache
            .get_or_connect(&connector, "host1", "/data", &AuthCreds::new(1000, 1000))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn different_hosts_create_different_connections() {
        let mut connector = MockNfsConnector::new();
        connector.expect_connect().times(2).returning(|_, _, _| {
            let mock = MockNfsOps::new();
            Ok(Box::new(mock))
        });

        let mut cache = ConnectionCache::new();
        let creds = AuthCreds::root();
        cache
            .get_or_connect(&connector, "host1", "/data", &creds)
            .await
            .unwrap();
        cache
            .get_or_connect(&connector, "host2", "/data", &creds)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn cache_connection_failure_propagates() {
        let mut connector = MockNfsConnector::new();
        connector.expect_connect().times(1).returning(|_, _, _| {
            Err(Box::new(NfsError::ConnectionLost) as Box<dyn std::error::Error + Send + Sync>)
        });

        let mut cache = ConnectionCache::new();
        let result = cache
            .get_or_connect(&connector, "host1", "/export", &AuthCreds::root())
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn cache_evicts_when_exceeding_max_entries() {
        let mut connector = MockNfsConnector::new();
        connector.expect_connect().returning(|_, _, _| {
            let mock = MockNfsOps::new();
            Ok(Box::new(mock))
        });

        let mut cache = ConnectionCache::with_max_entries(2);
        let creds = AuthCreds::root();

        cache
            .get_or_connect(&connector, "h1", "/e", &creds)
            .await
            .unwrap();
        cache
            .get_or_connect(&connector, "h2", "/e", &creds)
            .await
            .unwrap();
        cache
            .get_or_connect(&connector, "h3", "/e", &creds)
            .await
            .unwrap();

        assert!(
            cache.len() <= 2,
            "cache should not exceed max_entries=2, got {}",
            cache.len()
        );
    }

    #[tokio::test]
    async fn cache_evicts_least_recently_used_entry() {
        let mut connector = MockNfsConnector::new();
        connector.expect_connect().returning(|_, _, _| {
            let mock = MockNfsOps::new();
            Ok(Box::new(mock))
        });

        let mut cache = ConnectionCache::with_max_entries(2);
        let creds = AuthCreds::root();

        // Insert h1, then h2 (order: h1, h2)
        cache
            .get_or_connect(&connector, "h1", "/e", &creds)
            .await
            .unwrap();
        cache
            .get_or_connect(&connector, "h2", "/e", &creds)
            .await
            .unwrap();

        // Access h1 again (order becomes: h2, h1)
        cache
            .get_or_connect(&connector, "h1", "/e", &creds)
            .await
            .unwrap();

        // Insert h3 — should evict h2 (LRU), not h1 (recently used)
        cache
            .get_or_connect(&connector, "h3", "/e", &creds)
            .await
            .unwrap();

        assert_eq!(cache.len(), 2);
        // h1 should still be cached
        assert!(cache.contains_key("h1", "/e", &creds));
        // h2 should have been evicted
        assert!(!cache.contains_key("h2", "/e", &creds));
    }
}
