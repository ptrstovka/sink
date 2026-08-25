use std::time::Duration;

use uuid::Uuid;

pub(crate) const INITIAL_RECONNECT_DELAY: Duration = Duration::from_millis(100);
pub(crate) const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(2);

#[derive(Debug, Default)]
pub(crate) struct ReconnectBackoff {
    failures: u32,
}

impl ReconnectBackoff {
    pub(crate) fn reset(&mut self) {
        self.failures = 0;
    }

    pub(crate) fn next_delay(&mut self, session_id: Uuid) -> Duration {
        let exponent = self.failures.min(31);
        self.failures = self.failures.saturating_add(1);

        let ceiling_ms = INITIAL_RECONNECT_DELAY
            .as_millis()
            .saturating_mul(1_u128 << exponent)
            .min(MAX_RECONNECT_DELAY.as_millis()) as u64;
        let floor_ms = ceiling_ms / 2;
        let jitter_span = ceiling_ms.saturating_sub(floor_ms).saturating_add(1);
        let jitter = stable_jitter(session_id, exponent) % jitter_span;
        Duration::from_millis(floor_ms + jitter)
    }
}

fn stable_jitter(session_id: Uuid, attempt: u32) -> u64 {
    let mut value = u64::from_le_bytes(session_id.as_bytes()[..8].try_into().unwrap_or([0_u8; 8]))
        ^ u64::from(attempt);
    value ^= value >> 12;
    value ^= value << 25;
    value ^= value >> 27;
    value.wrapping_mul(0x2545_f491_4f6c_dd1d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exponential_backoff_is_jittered_deterministic_and_capped() {
        let session = Uuid::from_u128(0x1234);
        let mut first = ReconnectBackoff::default();
        let mut second = ReconnectBackoff::default();

        let first_run: Vec<_> = (0..20).map(|_| first.next_delay(session)).collect();
        let second_run: Vec<_> = (0..20).map(|_| second.next_delay(session)).collect();
        assert_eq!(first_run, second_run);
        assert!(first_run.iter().all(|delay| *delay <= MAX_RECONNECT_DELAY));
        assert!(first_run[0] >= INITIAL_RECONNECT_DELAY / 2);
        assert!(first_run[10] >= MAX_RECONNECT_DELAY / 2);
        assert!(first_run.iter().any(|delay| *delay < MAX_RECONNECT_DELAY));
    }

    #[test]
    fn reset_returns_to_the_initial_window() {
        let session = Uuid::from_u128(0x5678);
        let mut backoff = ReconnectBackoff::default();
        let initial = backoff.next_delay(session);
        for _ in 0..12 {
            let _ = backoff.next_delay(session);
        }
        backoff.reset();
        assert_eq!(backoff.next_delay(session), initial);
    }
}
