use std::ptr::read_volatile;

fn main() {
    let x = ttfb::ttfb("Hello, world!".to_string(), false);
    let x = &x;
    unsafe {
        let _x = read_volatile(x as *const _);
    }
}
