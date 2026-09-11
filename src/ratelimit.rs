//! Coarse per IP rate limiting for failed handshakes

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Counts failed authentication attempts per IP within a sliding window
///
/// Note: entries are only removed on a successful authentication, so the map
/// itself can still grow
#[derive(Debug)]
pub struct RateLimiter {
    attempts: HashMap<IpAddr, Vec<Instant>>,
    window: Duration,
    max_attempts: usize,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            attempts: HashMap::new(),
            window: Duration::from_secs(300),
            max_attempts: 5,
        }
    }

    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        if let Some(times) = self.attempts.get(ip) {
            let now = Instant::now();
            let recent: Vec<_> = times
                .iter()
                .filter(|&&t| now.duration_since(t) < self.window)
                .collect();
            return recent.len() >= self.max_attempts;
        }
        false
    }

    pub fn record_failure(&mut self, ip: IpAddr) {
        let now = Instant::now();
        let times = self.attempts.entry(ip).or_default();
        times.push(now);
        times.retain(|&t| now.duration_since(t) < self.window);
    }

    pub fn clear_attempts(&mut self, ip: &IpAddr) {
        self.attempts.remove(ip);
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}
