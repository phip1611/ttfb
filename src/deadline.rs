// SPDX-License-Identifier: MIT

//! The deadline of a measurement for async code.

use crate::TtfbError;
use std::time::{Duration, Instant};
use tokio::time::timeout_at;

/// The point in time by which a measurement must complete. Async code
/// enforces it with [`Deadline::run`].
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
    fn run() {
        let deadline = Deadline::after(Duration::from_millis(10));
        let result = run_in_tokio(deadline.run(pending::<Result<(), _>>()));
        assert_eq!(result, Err(TtfbError::Timeout(Duration::from_millis(10))));
        let deadline = Deadline::after(Duration::from_secs(10));
        assert_eq!(run_in_tokio(deadline.run(async { Ok(()) })), Ok(()));
    }
}
