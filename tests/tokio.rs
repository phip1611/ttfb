// SPDX-License-Identifier: MIT

use ttfb::{TtfbClient, TtfbError, TtfbOptions};

/// This test succeeds if `TtfbClient::measure()` doesn't raise a panic.
#[test]
fn can_run_ttfb_lib_from_tokio_runtime() {
    let tokio = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    tokio.block_on(async {
        let ttfb = TtfbClient::new(TtfbOptions::default()).measure("http://localhost:1");
        match ttfb {
            Err(TtfbError::CantConnectTcp(_)) => {}
            _ => panic!("Unexpected result: {ttfb:#?}"),
        }
    });
}
