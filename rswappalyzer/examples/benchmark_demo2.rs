// examples/benchmark_demo.rs
// 精准压力测试 + detect()真实性能测量版
// 运行：cargo run --example benchmark_demo --features embedded-rules --release

use http::header::{HeaderMap, HeaderName, HeaderValue};
use rswappalyzer::{RuleConfig, RuleOrigin, TechDetector};
use std::time::{Duration, Instant};

const BENCHMARK_LOOP_COUNT: usize = 1000;
const WARM_UP_LOOP: usize = 10;

#[derive(Default)]
struct TimeStat {
    total: Duration,
}

impl TimeStat {
    fn record(&mut self, d: Duration) {
        self.total += d;
    }

    fn avg_ms(&self, count: usize) -> f64 {
        self.total.as_secs_f64() * 1000.0 / count as f64
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ===== 1. 初始化检测器 =====
    let config = RuleConfig {
        origin: RuleOrigin::Embedded,
        ..RuleConfig::default()
    };
    let detector = TechDetector::with_embedded_rules(config)?;
    println!("✅ Detector initialized (embedded rules)");

    // ===== 2. 构造测试数据 =====
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("cache-control"),
        HeaderValue::from_static("private"),
    );
    headers.insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(
        HeaderName::from_static("x-powered-by"),
        HeaderValue::from_static("ASP.NET"),
    );
    headers.insert(
        HeaderName::from_static("set-cookie"),
        HeaderValue::from_static("ASP.NET_SessionId=1hmbvexm23c1gqaaptjqedhr; HttpOnly"),
    );

    let urls = &["https://example.com/"];

    // ⚠ 使用你原本的 HTML，不读文件、不依赖路径
    let html_body = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>test</title>
    <script src="/js/jquery-1.9.1.min.js"></script>
</head>
<body>
    <h1>Hello</h1>
</body>
</html>"#;

    let body_bytes = html_body.as_bytes();

    // ===== 3. 预热 =====
    println!("🔥 Warming up...");
    for _ in 0..WARM_UP_LOOP {
        let _ = detector.detect(&headers, urls, body_bytes).unwrap();
    }
    println!("🔥 Warm-up done");

    // ===== 4. 压测 =====
    let mut detect_time = TimeStat::default();
    let mut result_access_time = TimeStat::default();

    println!("🚀 Start benchmark: {} loops", BENCHMARK_LOOP_COUNT);
    let total_start = Instant::now();

    for i in 0..BENCHMARK_LOOP_COUNT {
        // detect 本体耗时
        let t0 = Instant::now();
        let result = detector.detect(&headers, urls, body_bytes).unwrap();
        detect_time.record(t0.elapsed());

        // 模拟业务读取结果（避免被编译器优化掉）
        let t1 = Instant::now();
        let _tech_count = result.technologies.len();
        result_access_time.record(t1.elapsed());

        if (i + 1) % 2000 == 0 {
            println!("Progress: {}/{}", i + 1, BENCHMARK_LOOP_COUNT);
        }
    }

    let total_elapsed = total_start.elapsed();

    // ===== 5. 报表 =====
    println!("================================================");
    println!("📊 Benchmark Result");
    println!("------------------------------------------------");
    println!("Total elapsed : {:.3} s", total_elapsed.as_secs_f64());
    println!(
        "QPS           : {:.2}",
        BENCHMARK_LOOP_COUNT as f64 / total_elapsed.as_secs_f64()
    );
    println!("------------------------------------------------");
    println!(
        "detect() avg  : {:.3} ms",
        detect_time.avg_ms(BENCHMARK_LOOP_COUNT)
    );
    println!(
        "result access : {:.6} ms",
        result_access_time.avg_ms(BENCHMARK_LOOP_COUNT)
    );
    println!("================================================");

    Ok(())
}
