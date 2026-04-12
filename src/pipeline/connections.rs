use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::Semaphore;

pub const DEFAULT_MAX_CONNECTIONS_PER_HOST: usize = 8;

pub struct HostConnectionPool {
    inner: DashMap<String, Arc<Semaphore>>,
    max_connections: usize,
}

impl HostConnectionPool {
    #[must_use]
    pub fn new(max_connections: usize) -> Self {
        let max_connections = max_connections.max(1);
        Self {
            inner: DashMap::new(),
            max_connections,
        }
    }

    #[must_use]
    pub fn get_semaphore(&self, host: &str) -> Arc<Semaphore> {
        self.inner
            .entry(host.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(self.max_connections)))
            .clone()
    }
}

impl Default for HostConnectionPool {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_CONNECTIONS_PER_HOST)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_creates_semaphore_for_new_host() {
        let pool = HostConnectionPool::default();
        let sem = pool.get_semaphore("host1");
        assert_eq!(sem.available_permits(), DEFAULT_MAX_CONNECTIONS_PER_HOST);
    }

    #[test]
    fn pool_returns_same_semaphore_for_same_host() {
        let pool = HostConnectionPool::default();
        let s1 = pool.get_semaphore("host1");
        let s2 = pool.get_semaphore("host1");
        assert!(Arc::ptr_eq(&s1, &s2));
    }

    #[test]
    fn pool_creates_separate_semaphores_per_host() {
        let pool = HostConnectionPool::default();
        let s1 = pool.get_semaphore("host1");
        let s2 = pool.get_semaphore("host2");
        assert!(!Arc::ptr_eq(&s1, &s2));
    }

    #[tokio::test]
    async fn pool_semaphore_limits_concurrent_permits() {
        let pool = HostConnectionPool::new(2);
        let sem = pool.get_semaphore("host1");
        let p1 = sem.acquire().await.unwrap();
        let _p2 = sem.acquire().await.unwrap();
        assert!(sem.try_acquire().is_err());
        drop(p1);
        assert!(sem.try_acquire().is_ok());
    }

    #[tokio::test]
    async fn pool_concurrent_creation_returns_same_semaphore() {
        let pool = Arc::new(HostConnectionPool::default());
        let mut handles = Vec::new();
        for _ in 0..10 {
            let p = Arc::clone(&pool);
            handles.push(tokio::task::spawn(async move { p.get_semaphore("host1") }));
        }
        let mut sems = Vec::new();
        for handle in handles {
            sems.push(handle.await.unwrap());
        }
        for sem in &sems[1..] {
            assert!(Arc::ptr_eq(&sems[0], sem));
        }
    }

    #[tokio::test]
    async fn pool_custom_max_connections() {
        let pool = HostConnectionPool::new(3);
        let sem = pool.get_semaphore("host1");
        let _p1 = sem.acquire().await.unwrap();
        let _p2 = sem.acquire().await.unwrap();
        let _p3 = sem.acquire().await.unwrap();
        assert!(sem.try_acquire().is_err());
    }

    #[tokio::test]
    async fn pool_default_eight_permits() {
        let pool = HostConnectionPool::default();
        let sem = pool.get_semaphore("host1");
        let mut permits = Vec::new();
        for _ in 0..8 {
            permits.push(sem.acquire().await.unwrap());
        }
        assert!(sem.try_acquire().is_err());
    }
}
