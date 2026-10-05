// SPDX-License-Identifier: MIT

use std::ptr::read_volatile;

fn main() {
    let x = ttfb::TtfbClient::new(ttfb::TtfbOptions::default()).measure("Hello, world!");
    let x = &x;
    unsafe {
        let _x = read_volatile(x as *const _);
    }
}
