//! Fixed-window rate limiter (per key and global, per minute).
//!
//! Memory is bounded by construction: a key only gets an entry while the
//! global budget still has room, so at most `global_per_min` keys exist.

use std::collections::HashMap;
use std::sync::Mutex;

struct Window {
    minute: u64,
    global: u32,
    keys: HashMap<String, u32>,
}

pub struct RateLimiter {
    global_per_min: u32,
    per_key_per_min: u32,
    window: Mutex<Window>,
}

impl RateLimiter {
    pub fn new(global_per_min: u32, per_key_per_min: u32) -> Self {
        RateLimiter {
            global_per_min,
            per_key_per_min,
            window: Mutex::new(Window { minute: 0, global: 0, keys: HashMap::new() }),
        }
    }

    /// Consume one unit for `key` at unix time `now`. `false` means refuse.
    pub fn allow(&self, key: &str, now: u64) -> bool {
        let mut w = self.window.lock().unwrap_or_else(|p| p.into_inner());
        let minute = now / 60;
        if w.minute != minute {
            w.minute = minute;
            w.global = 0;
            w.keys.clear();
        }
        let used = w.keys.get(key).copied().unwrap_or(0);
        if w.global >= self.global_per_min || used >= self.per_key_per_min {
            return false;
        }
        w.keys.insert(key.to_string(), used + 1);
        w.global += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_key_and_global_budgets() {
        let r = RateLimiter::new(3, 2);
        assert!(r.allow("a", 60));
        assert!(r.allow("a", 61));
        assert!(!r.allow("a", 62));
        assert!(r.allow("b", 62));
        assert!(!r.allow("c", 62));
        assert!(r.allow("a", 120));
    }

    #[test]
    fn survives_a_poisoned_lock() {
        let r = std::sync::Arc::new(RateLimiter::new(5, 5));
        let r2 = r.clone();
        let _ = std::thread::spawn(move || {
            let _g = r2.window.lock().unwrap();
            panic!("poison");
        })
        .join();
        assert!(r.allow("a", 1));
    }
}
