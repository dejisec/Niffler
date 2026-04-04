use std::sync::Mutex;
use std::time::{Duration, Instant};

use dashmap::DashMap;

pub const DEFAULT_ERROR_THRESHOLD: u32 = 50;
pub const DEFAULT_COOLDOWN_DURATION: Duration = Duration::from_secs(30);

struct HealthState {
    consecutive_errors: u32,
    cooldown_until: Option<Instant>,
}

pub struct HostHealth {
    state: Mutex<HealthState>,
    threshold: u32,
    cooldown_duration: Duration,
}

impl HostHealth {
    pub fn new(threshold: u32, cooldown_duration: Duration) -> Self {
        Self {
            state: Mutex::new(HealthState {
                consecutive_errors: 0,
                cooldown_until: None,
            }),
            threshold,
            cooldown_duration,
        }
    }

    pub fn record_error(&self) {
        let mut guard = self.state.lock().unwrap();
        guard.consecutive_errors += 1;
        if guard.consecutive_errors >= self.threshold {
            guard.cooldown_until = Some(Instant::now() + self.cooldown_duration);
        }
    }

    pub fn record_success(&self) {
        let mut guard = self.state.lock().unwrap();
        guard.consecutive_errors = 0;
        guard.cooldown_until = None;
    }

    pub fn is_in_cooldown(&self) -> bool {
        let guard = self.state.lock().unwrap();
        match guard.cooldown_until {
            Some(until) => Instant::now() < until,
            None => false,
        }
    }

    pub fn consecutive_errors(&self) -> u32 {
        self.state.lock().unwrap().consecutive_errors
    }
}

impl Default for HostHealth {
    fn default() -> Self {
        Self::new(DEFAULT_ERROR_THRESHOLD, DEFAULT_COOLDOWN_DURATION)
    }
}

pub struct HostHealthRegistry {
    inner: DashMap<String, HostHealth>,
    threshold: u32,
    cooldown_duration: Duration,
}

impl HostHealthRegistry {
    pub fn new(threshold: u32, cooldown_duration: Duration) -> Self {
        Self {
            inner: DashMap::new(),
            threshold,
            cooldown_duration,
        }
    }

    pub fn record_error(&self, host: &str) {
        self.inner
            .entry(host.to_string())
            .or_insert_with(|| HostHealth::new(self.threshold, self.cooldown_duration))
            .record_error();
    }

    pub fn record_success(&self, host: &str) {
        self.inner
            .entry(host.to_string())
            .or_insert_with(|| HostHealth::new(self.threshold, self.cooldown_duration))
            .record_success();
    }

    pub fn is_in_cooldown(&self, host: &str) -> bool {
        self.inner
            .get(host)
            .map(|h| h.is_in_cooldown())
            .unwrap_or(false)
    }

    pub fn consecutive_errors(&self, host: &str) -> u32 {
        self.inner
            .get(host)
            .map(|h| h.consecutive_errors())
            .unwrap_or(0)
    }
}

impl Default for HostHealthRegistry {
    fn default() -> Self {
        Self::new(DEFAULT_ERROR_THRESHOLD, DEFAULT_COOLDOWN_DURATION)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn host_health_record_success_resets_counter() {
        let h = HostHealth::new(100, Duration::from_secs(10));
        for _ in 0..10 {
            h.record_error();
        }
        h.record_success();
        assert_eq!(h.consecutive_errors(), 0);
    }

    #[test]
    fn host_health_cooldown_at_threshold() {
        let h = HostHealth::new(50, Duration::from_secs(30));
        for _ in 0..50 {
            h.record_error();
        }
        assert!(h.is_in_cooldown());
    }

    #[test]
    fn host_health_no_cooldown_below_threshold() {
        let h = HostHealth::new(50, Duration::from_secs(30));
        for _ in 0..49 {
            h.record_error();
        }
        assert!(!h.is_in_cooldown());
    }

    #[test]
    fn host_health_cooldown_with_zero_duration_expires_immediately() {
        let h = HostHealth::new(50, Duration::ZERO);
        for _ in 0..50 {
            h.record_error();
        }
        assert!(!h.is_in_cooldown());
    }

    #[test]
    fn host_health_success_clears_cooldown() {
        let h = HostHealth::new(50, Duration::from_secs(30));
        for _ in 0..50 {
            h.record_error();
        }
        assert!(h.is_in_cooldown());
        h.record_success();
        assert!(!h.is_in_cooldown());
        assert_eq!(h.consecutive_errors(), 0);
    }

    #[test]
    fn host_health_error_after_success_starts_fresh() {
        let h = HostHealth::new(100, Duration::from_secs(10));
        for _ in 0..49 {
            h.record_error();
        }
        h.record_success();
        h.record_error();
        assert_eq!(h.consecutive_errors(), 1);
    }

    #[test]
    fn host_health_custom_threshold() {
        let h = HostHealth::new(5, Duration::from_secs(10));
        for _ in 0..4 {
            h.record_error();
        }
        assert!(!h.is_in_cooldown());
        h.record_error(); // 5th error hits threshold
        assert!(h.is_in_cooldown());
    }

    #[tokio::test]
    async fn host_health_concurrent_error_recording() {
        let h = Arc::new(HostHealth::new(100, Duration::from_secs(10)));
        let mut handles = Vec::new();
        for _ in 0..10 {
            let h = Arc::clone(&h);
            handles.push(tokio::task::spawn(async move {
                h.record_error();
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }
        assert_eq!(h.consecutive_errors(), 10);
    }

    #[test]
    fn registry_tracks_multiple_hosts_independently() {
        let reg = HostHealthRegistry::default();
        for _ in 0..3 {
            reg.record_error("host1");
        }
        for _ in 0..7 {
            reg.record_error("host2");
        }
        assert_eq!(reg.consecutive_errors("host1"), 3);
        assert_eq!(reg.consecutive_errors("host2"), 7);
    }

    #[test]
    fn registry_record_success_resets_specific_host() {
        let reg = HostHealthRegistry::default();
        for _ in 0..10 {
            reg.record_error("host1");
            reg.record_error("host2");
        }
        reg.record_success("host1");
        assert_eq!(reg.consecutive_errors("host1"), 0);
        assert_eq!(reg.consecutive_errors("host2"), 10);
    }

    #[test]
    fn registry_is_in_cooldown_per_host() {
        let reg = HostHealthRegistry::new(5, Duration::from_secs(10));
        for _ in 0..5 {
            reg.record_error("host1");
        }
        for _ in 0..3 {
            reg.record_error("host2");
        }
        assert!(reg.is_in_cooldown("host1"));
        assert!(!reg.is_in_cooldown("host2"));
    }

    #[tokio::test]
    async fn registry_concurrent_access_multiple_hosts() {
        let reg = Arc::new(HostHealthRegistry::new(100, Duration::from_secs(10)));
        let mut handles = Vec::new();
        for _ in 0..10 {
            let r = Arc::clone(&reg);
            handles.push(tokio::task::spawn(async move {
                r.record_error("host1");
            }));
        }
        for _ in 0..10 {
            let r = Arc::clone(&reg);
            handles.push(tokio::task::spawn(async move {
                r.record_error("host2");
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }
        assert_eq!(reg.consecutive_errors("host1"), 10);
        assert_eq!(reg.consecutive_errors("host2"), 10);
    }

    #[tokio::test]
    async fn no_spurious_cooldown_after_success() {
        // Invariant: if consecutive_errors == 0, cooldown must be None.
        for _ in 0..200 {
            let h = Arc::new(HostHealth::new(1, Duration::from_secs(60)));
            let h1 = Arc::clone(&h);
            let h2 = Arc::clone(&h);

            let t1 = tokio::spawn(async move {
                h1.record_error();
            });
            let t2 = tokio::spawn(async move {
                h2.record_success();
            });
            t1.await.unwrap();
            t2.await.unwrap();

            if h.consecutive_errors() == 0 {
                assert!(
                    !h.is_in_cooldown(),
                    "BUG: cooldown set despite counter being 0 (TOCTOU race)"
                );
            }
        }
    }
}
