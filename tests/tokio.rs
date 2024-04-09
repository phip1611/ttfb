use ttfb::TtfbError;

/// This test succeeds if `ttfb::ttfb()` doesn't raise a panic.
#[test]
fn can_run_ttfb_lib_from_tokio_runtime() {
    let tokio = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    tokio.block_on(async {
        let ttfb = ttfb::ttfb("http://localhost:1", false);
        match ttfb {
            Err(TtfbError::CantConnectTcp(_)) => {}
            _ => panic!("Unexpected result: {ttfb:#?}"),
        }
    });
}
