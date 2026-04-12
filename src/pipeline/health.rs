use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use dashmap::DashMap;

pub const DEFAULT_ERROR_THRESHOLD: u32 = 10;
pub const DEFAULT_COOLDOWN_DURATION: Duration = Duration::from_secs(60);

const DEFAULT_WINDOW: Duration = Duration::from_secs(60);
const DEFAULT_ERROR_RATE_THRESHOLD: f64 = 0.8;
const DEFAULT_MAX_EVENTS: usize = 200;

#[derive(Debug, Clone, Copy)]
pub enum CooldownStrategy {
    Fixed(Duration),
    Exponential { base: Duration, max: Duration },
}

#[derive(Clone, Copy)]
struct Event {
    at: Instant,
    is_error: bool,
}

struct HealthState {
    events: VecDeque<Event>,
    trip_count: u32,
    cooldown_until: Option<Instant>,
}

pub struct HostHealth {
    state: Mutex<HealthState>,
    window: Duration,
    error_rate_threshold: f64,
    max_events: usize,
    min_samples: usize,
    cooldown_strategy: CooldownStrategy,
}

impl HostHealth {
    #[must_use]
    pub fn new(min_samples: u32, cooldown_duration: Duration) -> Self {
        Self {
            state: Mutex::new(HealthState {
                events: VecDeque::with_capacity(DEFAULT_MAX_EVENTS),
                trip_count: 0,
                cooldown_until: None,
            }),
            window: DEFAULT_WINDOW,
            error_rate_threshold: DEFAULT_ERROR_RATE_THRESHOLD,
            max_events: DEFAULT_MAX_EVENTS,
            min_samples: min_samples.max(1) as usize,
            cooldown_strategy: CooldownStrategy::Exponential {
                base: cooldown_duration,
                max: cooldown_duration.saturating_mul(64),
            },
        }
    }

    fn record_event(&self, is_error: bool) {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();

        if let Some(until) = guard.cooldown_until {
            if now < until {
                return;
            }
            // Cooldown expired — clear stale events for a clean recovery window
            guard.cooldown_until = None;
            guard.events.clear();
        }

        if guard.events.len() >= self.max_events {
            guard.events.pop_front();
        }
        guard.events.push_back(Event { at: now, is_error });

        let cutoff = now - self.window;
        while guard.events.front().is_some_and(|e| e.at < cutoff) {
            guard.events.pop_front();
        }

        let total = guard.events.len();
        if total < self.min_samples {
            return;
        }
        let errors = guard.events.iter().filter(|e| e.is_error).count();
        let rate = errors as f64 / total as f64;

        if is_error && rate >= self.error_rate_threshold {
            guard.trip_count += 1;
            let cooldown = match self.cooldown_strategy {
                CooldownStrategy::Fixed(d) => d,
                CooldownStrategy::Exponential { base, max } => {
                    let multiplier = 1u64 << (guard.trip_count - 1).min(10);
                    base.saturating_mul(multiplier as u32).min(max)
                }
            };
            guard.cooldown_until = Some(now + cooldown);
        } else if !is_error && rate < self.error_rate_threshold * 0.5 {
            guard.trip_count = 0;
        }
    }

    pub fn record_error(&self) {
        self.record_event(true);
    }

    pub fn record_success(&self) {
        self.record_event(false);
    }

    #[must_use]
    pub fn is_in_cooldown(&self) -> bool {
        let guard = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .cooldown_until
            .is_some_and(|until| Instant::now() < until)
    }

    #[must_use]
    pub fn error_count(&self) -> usize {
        let guard = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.events.iter().filter(|e| e.is_error).count()
    }

    #[must_use]
    pub fn trip_count(&self) -> u32 {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .trip_count
    }
}

impl Default for HostHealth {
    fn default() -> Self {
        Self::new(DEFAULT_ERROR_THRESHOLD, DEFAULT_COOLDOWN_DURATION)
    }
}

pub struct HostHealthRegistry {
    inner: DashMap<String, HostHealth>,
    min_samples: u32,
    cooldown_duration: Duration,
}

impl HostHealthRegistry {
    #[must_use]
    pub fn new(threshold: u32, cooldown_duration: Duration) -> Self {
        Self {
            inner: DashMap::new(),
            min_samples: threshold,
            cooldown_duration,
        }
    }

    pub fn record_error(&self, host: &str) {
        self.inner
            .entry(host.to_string())
            .or_insert_with(|| HostHealth::new(self.min_samples, self.cooldown_duration))
            .record_error();
    }

    pub fn record_success(&self, host: &str) {
        self.inner
            .entry(host.to_string())
            .or_insert_with(|| HostHealth::new(self.min_samples, self.cooldown_duration))
            .record_success();
    }

    #[must_use]
    pub fn is_in_cooldown(&self, host: &str) -> bool {
        self.inner
            .get(host)
            .map(|h| h.is_in_cooldown())
            .unwrap_or(false)
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
    fn host_health_trips_on_high_error_rate() {
        let h = HostHealth::new(10, Duration::from_secs(60));
        for _ in 0..10 {
            h.record_error();
        }
        assert!(h.is_in_cooldown());
    }

    #[test]
    fn host_health_no_trip_below_min_samples() {
        let h = HostHealth::new(10, Duration::from_secs(60));
        for _ in 0..9 {
            h.record_error();
        }
        assert!(!h.is_in_cooldown());
    }

    #[test]
    fn host_health_cooldown_with_zero_duration_expires_immediately() {
        let h = HostHealth::new(10, Duration::ZERO);
        for _ in 0..10 {
            h.record_error();
        }
        assert!(!h.is_in_cooldown());
    }

    #[test]
    fn host_health_success_clears_cooldown() {
        let h = HostHealth::new(5, Duration::from_secs(60));
        for _ in 0..5 {
            h.record_error();
        }
        assert!(h.is_in_cooldown());
        // Simulate cooldown expiry by using zero-duration strategy
        let h2 = HostHealth::new(5, Duration::ZERO);
        for _ in 0..5 {
            h2.record_error();
        }
        assert!(!h2.is_in_cooldown());
        // After enough successes, trip_count resets
        for _ in 0..10 {
            h2.record_success();
        }
        assert_eq!(h2.trip_count(), 0);
    }

    #[test]
    fn host_health_default_trips_after_10_errors() {
        let h = HostHealth::default();
        for _ in 0..9 {
            h.record_error();
        }
        assert!(!h.is_in_cooldown());
        h.record_error();
        assert!(h.is_in_cooldown());
    }

    #[test]
    fn host_health_error_after_success_mixed_rate() {
        let h = HostHealth::new(10, Duration::from_secs(60));
        // 4 errors, 1 success, 4 errors = 8/9 errors, but < min_samples(10)
        for _ in 0..4 {
            h.record_error();
        }
        h.record_success();
        for _ in 0..4 {
            h.record_error();
        }
        assert!(!h.is_in_cooldown());
        // 10th event: error, rate = 9/10 = 0.9 >= 0.8 → trip
        h.record_error();
        assert!(h.is_in_cooldown());
    }

    #[tokio::test]
    async fn host_health_concurrent_error_recording() {
        let h = Arc::new(HostHealth::new(200, Duration::from_secs(10)));
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
        assert_eq!(h.error_count(), 10);
    }

    #[test]
    fn registry_tracks_multiple_hosts_independently() {
        let reg = HostHealthRegistry::new(5, Duration::from_secs(60));
        for _ in 0..5 {
            reg.record_error("host1");
        }
        for _ in 0..3 {
            reg.record_error("host2");
        }
        assert!(reg.is_in_cooldown("host1"));
        assert!(!reg.is_in_cooldown("host2"));
    }

    #[test]
    fn registry_record_success_resets_specific_host() {
        let reg = HostHealthRegistry::new(5, Duration::ZERO);
        for _ in 0..5 {
            reg.record_error("host1");
            reg.record_error("host2");
        }
        // Both tripped with zero-duration cooldown (already expired)
        // Now feed successes to host1 to reset trip_count
        for _ in 0..10 {
            reg.record_success("host1");
        }
        // host1 should have trip_count=0, host2 should still have trip_count>0
        let h1 = reg.inner.get("host1").unwrap();
        let h2 = reg.inner.get("host2").unwrap();
        assert_eq!(h1.trip_count(), 0);
        assert!(h2.trip_count() > 0);
    }

    #[test]
    fn registry_is_in_cooldown_per_host() {
        let reg = HostHealthRegistry::new(5, Duration::from_secs(60));
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
    async fn no_spurious_cooldown_after_success() {
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

            // After both events, if the last event was success and rate is
            // below threshold, there should be no cooldown (assuming the
            // success came after the error in time).
            // With the new rate-based system, this is naturally handled:
            // 1 error + 1 success = 50% rate < 80% threshold → no trip.
            // Unless only the error was recorded when checked.
            // The invariant: if trip_count == 0, cooldown should be None.
            if h.trip_count() == 0 {
                assert!(
                    !h.is_in_cooldown(),
                    "BUG: cooldown set despite trip_count being 0 (TOCTOU race)"
                );
            }
        }
    }

    #[test]
    fn host_health_gradual_degradation_trips() {
        let h = HostHealth::new(10, Duration::from_secs(60));
        // 8 errors + 2 successes = 80% error rate at exactly min_samples
        for _ in 0..8 {
            h.record_error();
        }
        h.record_success();
        h.record_success();
        assert!(!h.is_in_cooldown());
        // One more error: 9/11 ≈ 81.8% → trips
        h.record_error();
        assert!(h.is_in_cooldown());
    }

    #[test]
    fn host_health_intermittent_success_prevents_trip() {
        let h = HostHealth::new(10, Duration::from_secs(60));
        // Alternate: error, error, success pattern → ~67% error rate < 80%
        for _ in 0..10 {
            h.record_error();
            h.record_error();
            h.record_success();
        }
        assert!(!h.is_in_cooldown());
    }

    #[test]
    fn host_health_exponential_cooldown_increases() {
        let base = Duration::from_millis(100);
        let max = Duration::from_secs(10);
        let h = HostHealth {
            state: Mutex::new(HealthState {
                events: VecDeque::new(),
                trip_count: 0,
                cooldown_until: None,
            }),
            window: DEFAULT_WINDOW,
            error_rate_threshold: DEFAULT_ERROR_RATE_THRESHOLD,
            max_events: DEFAULT_MAX_EVENTS,
            min_samples: 3,
            cooldown_strategy: CooldownStrategy::Exponential { base, max },
        };

        // First trip: min_samples errors
        for _ in 0..3 {
            h.record_error();
        }
        assert!(h.is_in_cooldown());
        assert_eq!(h.trip_count(), 1);

        // Manually expire cooldown for next trip
        {
            let mut guard = h.state.lock().unwrap();
            guard.cooldown_until = None;
            guard.events.clear();
        }

        // Second trip
        for _ in 0..3 {
            h.record_error();
        }
        assert!(h.is_in_cooldown());
        assert_eq!(h.trip_count(), 2);

        // Manually expire and trip again
        {
            let mut guard = h.state.lock().unwrap();
            guard.cooldown_until = None;
            guard.events.clear();
        }

        for _ in 0..3 {
            h.record_error();
        }
        assert_eq!(h.trip_count(), 3);
        // trip_count=3 → multiplier=4 → 400ms cooldown
        // Verify still in cooldown (400ms hasn't elapsed)
        assert!(h.is_in_cooldown());
    }

    #[tokio::test]
    async fn registry_concurrent_access_multiple_hosts() {
        let reg = Arc::new(HostHealthRegistry::new(200, Duration::from_secs(10)));
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
        let h1 = reg.inner.get("host1").unwrap();
        let h2 = reg.inner.get("host2").unwrap();
        assert_eq!(h1.error_count(), 10);
        assert_eq!(h2.error_count(), 10);
    }
}
