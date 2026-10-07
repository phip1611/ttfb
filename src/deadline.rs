// SPDX-License-Identifier: MIT

//! The deadline of a measurement.

use crate::TtfbError;
use async_io::Timer;
use futures_lite::future;
use std::time::{Duration, Instant};

/// The point in time by which a measurement must complete, as enforced by
/// [`Deadline::run`].
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
        let timeout = async {
            Timer::at(self.instant).await;
            Err(TtfbError::Timeout(self.timeout))
        };
        future::or(future, timeout).await
    }
}

#[cfg(test)]
impl Deadline {
    /// Creates a deadline for tests. It is longer than the default timeout, as
    /// the network tests use external sites, which are sometimes slow.
    pub fn for_tests() -> Self {
        Self::after(Duration::from_secs(30))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_io::block_on;
    use std::future::pending;

    #[test]
    fn run() {
        let deadline = Deadline::after(Duration::from_millis(10));
        let result = block_on(deadline.run(pending::<Result<(), _>>()));
        assert_eq!(result, Err(TtfbError::Timeout(Duration::from_millis(10))));
        let deadline = Deadline::after(Duration::from_secs(10));
        assert_eq!(block_on(deadline.run(async { Ok(()) })), Ok(()));
    }
}
