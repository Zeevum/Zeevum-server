//! Rate limiting, in front of the things that are expensive to do for a
//! stranger: a TLS handshake, a proof of work, a database write.
//!
//! Three limits share one map keyed by address:
//! - failed handshakes (L1), which existed before this module grew;
//! - accounts registered per address (L2);
//! - connections per address (L4), checked before TLS so that a refused
//!   address costs the server nothing but the accept.
//!
//! The fourth limit (L3, frames per connection) is a [`TokenBucket`] that
//! lives in the connection itself and shares nothing with anyone.
//!
//! The map is bounded from above: counters expire with their windows, and
//! past the ceiling the least recently touched entry is evicted. Whichever
//! comes first, an attacker with a million addresses cannot buy more memory
//! than the ceiling.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Failed handshakes before an address is not served anymore. Small on
/// purpose: a legitimate client fails once, maybe twice.
const HANDSHAKE_ATTEMPTS: usize = 5;
const HANDSHAKE_WINDOW: Duration = Duration::from_secs(300);
/// The window for L4. Short, because the point is to survive a burst of
/// connections, not to ban an address.
const CONNECTION_WINDOW: Duration = Duration::from_secs(10);
/// The window for L2. An hour, because a good account is slow to make and
/// a throwaway one is fast.
const REGISTRATION_WINDOW: Duration = Duration::from_secs(3600);
/// How many addresses the map keeps. Beyond this the least recently
/// touched entry is evicted. A normal server meets a lifetime of normal
/// addresses without ever reaching it; the number is about attackers with
/// address pools.
pub const MAX_TRACKED_IPS: usize = 10_000;

/// One address, three counters. Every deque only holds timestamps inside
/// its own window, so the length of a counter is its score.
struct IpEntry {
    handshake_failures: VecDeque<Instant>,
    registrations: VecDeque<Instant>,
    connections: VecDeque<Instant>,
    /// What the ceiling evicts by.
    last_touched: Instant,
}

impl Default for IpEntry {
    fn default() -> Self {
        Self {
            handshake_failures: VecDeque::new(),
            registrations: VecDeque::new(),
            connections: VecDeque::new(),
            // Overwritten by `entry` on the same breath; `Instant` simply
            // has no cheaper placeholder.
            last_touched: Instant::now(),
        }
    }
}

/// Everything that is per-address. One `Mutex` in the `AppContext` guards
/// it; every operation under it is a few instructions over one entry, so
/// there is nothing here to shard yet.
pub struct RateLimiter {
    entries: HashMap<IpAddr, IpEntry>,
    max_registrations: usize,
    max_connections: usize,
    max_tracked_ips: usize,
}

impl RateLimiter {
    pub fn new(max_registrations: usize, max_connections: usize, max_tracked_ips: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_registrations,
            max_connections,
            max_tracked_ips,
        }
    }

    /// The entry for an address, created on first sight. When the map is at
    /// its ceiling, the entry touched longest ago makes room first.
    fn entry(&mut self, ip: IpAddr, now: Instant) -> &mut IpEntry {
        if !self.entries.contains_key(&ip) && self.entries.len() >= self.max_tracked_ips {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_touched)
                .map(|(key, _)| *key);
            if let Some(oldest) = oldest {
                self.entries.remove(&oldest);
            }
        }
        let entry = self.entries.entry(ip).or_default();
        entry.last_touched = now;
        entry
    }

    /// L4: records the connection and answers whether it may proceed.
    /// Recording and checking are one call on purpose, the same way an
    /// audit is: a caller cannot forget half of it.
    pub fn connection_allowed(&mut self, ip: IpAddr, now: Instant) -> bool {
        let max = self.max_connections;
        let entry = self.entry(ip, now);
        entry
            .connections
            .retain(|t| now.duration_since(*t) < CONNECTION_WINDOW);
        if entry.connections.len() >= max {
            return false;
        }
        entry.connections.push_back(now);
        true
    }

    /// L1: whether the address has failed too many handshakes lately.
    pub fn handshake_blocked(&mut self, ip: IpAddr, now: Instant) -> bool {
        let entry = self.entry(ip, now);
        entry
            .handshake_failures
            .retain(|t| now.duration_since(*t) < HANDSHAKE_WINDOW);
        entry.handshake_failures.len() >= HANDSHAKE_ATTEMPTS
    }

    /// L1: a failed handshake, counted per address. Only bad credentials
    /// count, the caller decides what that means.
    pub fn record_handshake_failure(&mut self, ip: IpAddr, now: Instant) {
        let entry = self.entry(ip, now);
        entry
            .handshake_failures
            .retain(|t| now.duration_since(*t) < HANDSHAKE_WINDOW);
        entry.handshake_failures.push_back(now);
    }

    /// A successful handshake forgives the address its past failures.
    pub fn clear_handshake_failures(&mut self, ip: IpAddr, now: Instant) {
        if let Some(entry) = self.entries.get_mut(&ip) {
            entry.handshake_failures.clear();
            entry.last_touched = now;
        }
    }

    /// L2: whether the address may register one more account.
    pub fn registration_blocked(&mut self, ip: IpAddr, now: Instant) -> bool {
        let max = self.max_registrations;
        let entry = self.entry(ip, now);
        entry
            .registrations
            .retain(|t| now.duration_since(*t) < REGISTRATION_WINDOW);
        entry.registrations.len() >= max
    }

    /// L2: an account that exists, not an attempt that was refused.
    pub fn record_registration(&mut self, ip: IpAddr, now: Instant) {
        let entry = self.entry(ip, now);
        entry
            .registrations
            .retain(|t| now.duration_since(*t) < REGISTRATION_WINDOW);
        entry.registrations.push_back(now);
    }

    /// For tests: the map must never grow past its ceiling, this is how
    /// they see that it does not.
    pub fn tracked(&self) -> usize {
        self.entries.len()
    }
}

/// L3: frames per connection. Two connections of one user are two buckets,
/// and none of this needs a lock.
pub struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_per_sec: f64,
    /// Frames that had to wait since the last frame that did not. A frame
    /// arriving with a token ready resets it: the client slowed down, and
    /// is forgiven.
    starved: u32,
    /// How many starved frames before the connection is cut. Twice the
    /// burst: a legitimate paste never sees it, a flood reaches it in
    /// seconds.
    cutoff: u32,
    last: Instant,
}

/// What the bucket says about one frame.
pub enum Verdict {
    /// Process it now.
    Now,
    /// The bucket is empty; wait this long, then process.
    Wait(Duration),
    /// The client has been outpacing the refill for too long. Disconnect.
    Cut,
}

impl TokenBucket {
    pub fn new(burst: u32, per_sec: u32) -> Self {
        let capacity = burst as f64;
        Self {
            tokens: capacity,
            capacity,
            refill_per_sec: per_sec as f64,
            starved: 0,
            cutoff: burst.saturating_mul(2),
            last: Instant::now(),
        }
    }

    /// Refills by the time passed, then takes one token for the frame — or
    /// says how long to wait for one, or that enough is enough.
    ///
    /// A waiting frame borrows its token right away, so the wait itself
    /// does not refill the bucket for the next frame: without the borrow a
    /// flood would alternate Wait/Now forever and never reach the cut.
    pub fn verdict(&mut self, now: Instant) -> Verdict {
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            self.starved = 0;
            Verdict::Now
        } else {
            self.starved += 1;
            if self.starved >= self.cutoff {
                Verdict::Cut
            } else {
                // In debt the honest wait would grow with every frame.
                // One token's worth is enough: the debt is counted by
                // `starved`, not by making the client wait longer and
                // longer.
                let missing = 1.0 - self.tokens.max(0.0);
                let wait = missing / self.refill_per_sec;
                self.tokens -= 1.0;
                Verdict::Wait(Duration::from_secs_f64(wait))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last_octet: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, last_octet))
    }

    /// The ceiling is the whole point of the map: without it, an attacker
    /// with a pool of addresses buys memory forever.
    #[test]
    fn the_map_never_grows_past_its_ceiling() {
        let mut limiter = RateLimiter::new(3, 5, 100);
        let now = Instant::now();

        for i in 0..500u32 {
            let addr = IpAddr::V4(std::net::Ipv4Addr::new(10, (i >> 8) as u8, i as u8, 1));
            assert!(
                limiter.connection_allowed(addr, now),
                "a fresh address must always fit"
            );
        }

        assert!(
            limiter.tracked() <= 100,
            "the map grew to {}",
            limiter.tracked()
        );
    }

    #[test]
    fn five_failed_handshakes_block_the_address_and_a_success_forgives() {
        let mut limiter = RateLimiter::new(3, 5, 100);
        let now = Instant::now();

        for _ in 0..5 {
            limiter.record_handshake_failure(ip(1), now);
        }
        assert!(limiter.handshake_blocked(ip(1), now));

        limiter.clear_handshake_failures(ip(1), now);
        assert!(!limiter.handshake_blocked(ip(1), now));

        // The block dies with its window, like everything else here.
        for _ in 0..5 {
            limiter.record_handshake_failure(ip(1), now);
        }
        assert!(!limiter.handshake_blocked(ip(1), now + HANDSHAKE_WINDOW + Duration::from_secs(1)));
    }

    #[test]
    fn the_fourth_registration_from_an_address_is_refused_for_an_hour() {
        let mut limiter = RateLimiter::new(3, 5, 100);
        let now = Instant::now();

        for _ in 0..3 {
            limiter.record_registration(ip(1), now);
        }
        assert!(limiter.registration_blocked(ip(1), now));
        assert!(
            !limiter
                .registration_blocked(ip(1), now + REGISTRATION_WINDOW + Duration::from_secs(1))
        );
    }

    #[test]
    fn the_sixth_connection_in_a_burst_is_refused() {
        let mut limiter = RateLimiter::new(3, 5, 100);
        let now = Instant::now();

        for _ in 0..5 {
            assert!(limiter.connection_allowed(ip(1), now));
        }
        assert!(!limiter.connection_allowed(ip(1), now));
        assert!(
            limiter.connection_allowed(ip(1), now + CONNECTION_WINDOW + Duration::from_secs(1))
        );
    }

    /// Looking must not cost: an address checked a hundred times without
    /// a single account created still has its whole allowance.
    #[test]
    fn checking_an_address_costs_no_allowance() {
        let mut limiter = RateLimiter::new(3, 5, 100);
        let now = Instant::now();

        assert!(!limiter.registration_blocked(ip(1), now));
        assert!(!limiter.registration_blocked(ip(1), now));
    }

    #[test]
    fn a_burst_the_size_of_the_bucket_passes_without_waiting() {
        let mut bucket = TokenBucket::new(5, 1);
        let now = Instant::now();

        for _ in 0..5 {
            assert!(matches!(bucket.verdict(now), Verdict::Now));
        }
    }

    /// A flow faster than the refill is paced, and cut after twice the
    /// burst in starved frames — not a frame sooner.
    #[test]
    fn a_flow_faster_than_the_refill_is_paced_and_then_cut() {
        let mut bucket = TokenBucket::new(5, 1);
        let now = Instant::now();

        for _ in 0..5 {
            bucket.verdict(now);
        }

        let mut waited = 0;
        loop {
            match bucket.verdict(now + Duration::from_millis(waited)) {
                Verdict::Wait(_) => waited += 1,
                Verdict::Now => panic!("the bucket was not empty"),
                Verdict::Cut => break,
            }
        }
        // Nine waits, the tenth starved frame is the cut.
        assert_eq!(waited, 9, "the cut came after {waited} waits");
    }

    /// A pause refills the bucket and resets the starvation: one burst,
    /// then another an hour later, is two bursts, not a flood.
    #[test]
    fn a_pause_refills_the_bucket_and_forgives_the_starvation() {
        let mut bucket = TokenBucket::new(2, 1);
        let now = Instant::now();

        bucket.verdict(now);
        bucket.verdict(now);
        assert!(matches!(bucket.verdict(now), Verdict::Wait(_)));

        // A long pause: the refill is capped at the capacity, so both
        // tokens are back and two frames are served immediately.
        assert!(matches!(
            bucket.verdict(now + Duration::from_secs(5)),
            Verdict::Now
        ));
        assert!(matches!(
            bucket.verdict(now + Duration::from_secs(5)),
            Verdict::Now
        ));

        // The starvation counter started over: three starved frames do not
        // cut a bucket whose cutoff is four, the fourth does.
        assert!(matches!(
            bucket.verdict(now + Duration::from_secs(5)),
            Verdict::Wait(_)
        ));
        assert!(matches!(
            bucket.verdict(now + Duration::from_secs(5)),
            Verdict::Wait(_)
        ));
        assert!(matches!(
            bucket.verdict(now + Duration::from_secs(5)),
            Verdict::Wait(_)
        ));
        assert!(matches!(
            bucket.verdict(now + Duration::from_secs(5)),
            Verdict::Cut
        ));
    }
}
