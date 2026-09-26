//! Cooperative Kitrove launch serialization, not control over foreign runtimes.
use crate::ProcessRefused;
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

static LAUNCH_GATE: Mutex<()> = Mutex::new(());

/// Holds the reviewed Kitrove launch boundary. Never retain across child waits,
/// output reads or nested launch calls. External code does not participate in it.
pub struct LaunchGuard<'a> {
    _guard: MutexGuard<'a, ()>,
}

/// Acquire the cooperative launch gate with bounded polling. Poisoning refuses.
/// Callers must keep descriptor preparation and spawn inside the same guard.
pub fn acquire_launch_guard(timeout: Duration) -> Result<LaunchGuard<'static>, ProcessRefused> {
    acquire(&LAUNCH_GATE, timeout)
}

fn acquire(lock: &Mutex<()>, timeout: Duration) -> Result<LaunchGuard<'_>, ProcessRefused> {
    let deadline = Instant::now().checked_add(timeout).ok_or(ProcessRefused)?;
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(ProcessRefused)?;
        match lock.try_lock() {
            Ok(guard) => return Ok(LaunchGuard { _guard: guard }),
            Err(TryLockError::Poisoned(_)) => return Err(ProcessRefused),
            Err(TryLockError::WouldBlock) => {
                std::thread::sleep(remaining.min(Duration::from_millis(5)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contention_is_bounded_and_drop_releases_ownership() {
        let lock = Mutex::new(());
        let held = acquire(&lock, Duration::from_secs(1)).unwrap();
        assert!(acquire(&lock, Duration::from_millis(1)).is_err());
        drop(held);
        assert!(acquire(&lock, Duration::from_secs(1)).is_ok());
        assert!(acquire(&lock, Duration::ZERO).is_err());
        assert!(acquire(&lock, Duration::MAX).is_err());
    }

    #[test]
    fn poisoned_gate_refuses_instead_of_bypassing_serialization() {
        let lock = Mutex::new(());
        let _ = std::panic::catch_unwind(|| {
            let _held = lock.lock().unwrap();
            panic!("test poisoning");
        });
        assert!(acquire(&lock, Duration::from_secs(1)).is_err());
    }
}
