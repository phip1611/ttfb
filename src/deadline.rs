// SPDX-License-Identifier: MIT

//! The deadline of a measurement for async and blocking code.

use crate::TtfbError;
use std::time::{Duration, Instant};
use tokio::time::timeout_at;

/// The point in time by which a measurement must complete. Async code
/// enforces it with [`Deadline::run`], blocking code with
/// [`Deadline::remaining`].
#[derive(Clone, Copy, Debug)]
pub struct Deadline {
    /// The timeout the deadline was created with, for the error message.
    timeout: Duration,
    /// The deadline.
    instant: Instant,
}

impl Deadline {
    /// Creates the deadline `timeout` from now.
    pub fn after(timeout: Duration) -> Self {
        Self {
            timeout,
            instant: Instant::now() + timeout,
        }
    }

    /// Returns the time until the deadline. Fails if the deadline passed.
    pub fn remaining(self) -> Result<Duration, TtfbError> {
        // Socket timeouts reject zero.
        match self.instant.checked_duration_since(Instant::now()) {
            Some(remaining) if !remaining.is_zero() => Ok(remaining),
            _ => Err(TtfbError::Timeout(self.timeout)),
        }
    }

    /// Replaces `error` with the timeout error if the deadline passed, as the
    /// deadline most likely caused it.
    pub fn explain(self, error: TtfbError) -> TtfbError {
        match self.remaining() {
            Ok(_) => error,
            Err(timeout) => timeout,
        }
    }

    /// Runs `future` until it completes or the deadline passes.
    pub async fn run<T>(
        self,
        future: impl Future<Output = Result<T, TtfbError>>,
    ) -> Result<T, TtfbError> {
        timeout_at(self.instant.into(), future)
            .await
            .unwrap_or_else(|_| Err(TtfbError::Timeout(self.timeout)))
    }
}

#[cfg(test)]
impl Deadline {
    /// Creates a deadline for tests that don't depend on it.
    pub fn for_tests() -> Self {
        Self::after(crate::TtfbOptions::DEFAULT_TIMEOUT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run_in_tokio;
    use std::future::pending;

    #[test]
    fn remaining() {
        let remaining = Deadline::after(Duration::from_secs(10)).remaining();
        assert!(matches!(remaining, Ok(remaining) if remaining <= Duration::from_secs(10)));
        assert_eq!(
            Deadline::after(Duration::ZERO).remaining(),
            Err(TtfbError::Timeout(Duration::ZERO))
        );
    }

    #[test]
    fn explain() {
        let error = || TtfbError::NoHttpResponse;
        let timeout = Duration::from_secs(10);
        assert_eq!(Deadline::after(timeout).explain(error()), error());
        assert_eq!(
            Deadline::after(Duration::ZERO).explain(error()),
            TtfbError::Timeout(Duration::ZERO)
        );
    }

    #[test]
    fn run() {
        let deadline = Deadline::after(Duration::from_millis(10));
        let result = run_in_tokio(deadline.run(pending::<Result<(), _>>()));
        assert_eq!(result, Err(TtfbError::Timeout(Duration::from_millis(10))));
        let deadline = Deadline::after(Duration::from_secs(10));
        assert_eq!(run_in_tokio(deadline.run(async { Ok(()) })), Ok(()));
    }
}
