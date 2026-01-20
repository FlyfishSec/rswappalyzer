use std::time::Instant;

/// 极轻量时间探针
#[inline(always)]
pub fn time_it<T, F: FnOnce() -> T>(label: &str, f: F) -> T {
    let start = Instant::now();
    let ret = f();
    let cost = start.elapsed();
    eprintln!("[TIME] {:<40} {:?}", label, cost);
    ret
}
