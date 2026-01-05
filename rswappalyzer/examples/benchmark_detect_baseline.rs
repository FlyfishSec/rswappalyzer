// examples/benchmark_demo.rs
// rswappalyzer 指纹检测 专业压力测试 & 基准性能测试
// 标准调用方式: 全局初始化 + 异步detector::detect检测 (内部懒加载最优实现)
// 测试目标: 高并发场景下的真实性能指标(QPS/耗时/稳定性)
// 运行命令: cargo run --example benchmark_demo --features embedded-rules --release
use log::warn;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use rswappalyzer::{DetectResult, RuleConfig, detector, init_global_detector};
use std::time::Instant;

/// 压测核心配置项 - 按需调整，建议循序渐进 1万 → 10万 → 100万
const BENCHMARK_TOTAL_CALL: u64 = 10000; // 正式压测总调用次数
const BENCHMARK_WARM_UP_CALL: u64 = 1000; // 预热调用次数，消除懒加载/初始化影响
const BENCHMARK_PROGRESS_STEP: u64 = 10000; // 压测进度打印步长，避免刷屏影响性能
const BASE_TEST_SAMPLE: usize = 100; // 单次基准测试采样量

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化日志，适配业务中的warn日志输出
    env_logger::init();

    // 1. 全局初始化指纹检测器 - 与业务代码完全一致的初始化方式
    // 内部实现懒加载，全局唯一实例，生产环境最优写法
    let rule_config = RuleConfig::default();
    init_global_detector(rule_config).await?;

    // 打印压测基础信息
    println!("rswappalyzer 指纹检测 压力测试开始");
    println!("初始化状态: 全局检测器已加载，启用内置规则库 | 编译模式: Release(全优化)");
    println!(
        "测试配置: 预热次数 = {}, 压测总次数 = {}",
        BENCHMARK_WARM_UP_CALL, BENCHMARK_TOTAL_CALL
    );
    println!("------------------------------------------------------------------------------");

    // 2. 构造生产级真实测试数据 - 贴近业务真实请求场景
    // 包含主流Web技术栈特征头、Cookie、响应体，压测数据真实有效
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("cache-control"),
        HeaderValue::from_static("private"),
    );
    headers.insert(
        HeaderName::from_static("transfer-encoding"),
        HeaderValue::from_static("chunked"),
    );
    headers.insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(
        HeaderName::from_static("set-cookie"),
        HeaderValue::from_static("ASP.NET_SessionId=1hmbvexm23c1gqaaptjqedhr; path=/; HttpOnly"),
    );
    headers.insert(
        HeaderName::from_static("p3p"),
        HeaderValue::from_static("CP=CAO PSA OUR"),
    );
    headers.insert(
        HeaderName::from_static("x-powered-by"),
        HeaderValue::from_static("ASP.NET"),
    );
    headers.insert(
        HeaderName::from_static("access-control-allow-origin"),
        HeaderValue::from_static("*"),
    );
    headers.insert(
        HeaderName::from_static("date"),
        HeaderValue::from_static("Thu, 01 Jan 2026 02:37:48 GMT"),
    );

    // 与业务代码一致: urls传空数组 &[]
    let test_urls = &[];
    // 真实业务HTML响应体，包含JS/CSS/前端框架指纹特征
    let test_html_body = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>business page</title>
    <link rel="stylesheet" href="/css/iconfont.min.css" />
    <script src="/js/jquery-1.9.1.min.js"></script>
    <script src="/js/gVerify.js"></script>
</head>
<body>
    <div class="container"></div>
    <script>window.onload = function(){};</script>
</body>
</html>"#;
    let test_body_bytes = test_html_body.as_bytes();

    // 3. 执行预热调用 - 关键必要步骤
    // 消除影响: 全局懒加载初始化、正则缓存加载、内存页预分配、CPU分支预测缓存
    // 预热后所有压测数据，完全反映真实的detect检测性能，无初始化额外耗时
    println!("执行预热调用，消除初始化性能干扰...");
    for _ in 0..BENCHMARK_WARM_UP_CALL {
        let _ = detector::detect(&headers, test_urls, test_body_bytes).await;
    }
    println!("预热完成，开始正式异步压测...");
    println!("------------------------------------------------------------------------------");

    // 4. 正式高并发异步压测 - 核心逻辑【和你的业务代码完全一致】
    // 百分百复用你业务中的match错误处理+兜底空结果+warn日志，无任何修改
    let start_time = Instant::now();
    for index in 0..BENCHMARK_TOTAL_CALL {
        let _technology = match detector::detect(&headers, test_urls, test_body_bytes).await {
            Ok(techs) => techs,
            Err(e) => {
                warn!("rswappalyzer识别失败: {}", e);
                DetectResult {
                    technologies: Vec::new(),
                }
            }
        };

        // 按步长打印进度，避免高频IO输出导致压测数据失真
        if (index + 1) % BENCHMARK_PROGRESS_STEP == 0 {
            println!(
                "压测进度: 已完成 {} / {} 次指纹检测调用",
                index + 1,
                BENCHMARK_TOTAL_CALL
            );
        }
    }
    let total_elapsed = start_time.elapsed();

    // 5. 核心性能指标计算 & 专业报表输出
    // 行业标准性能指标，无冗余，精准统计，指标维度完整
    let total_sec = total_elapsed.as_secs_f64();
    let total_ms = total_sec * 1000.0;
    let avg_cost_ms = total_ms / BENCHMARK_TOTAL_CALL as f64;
    let qps = BENCHMARK_TOTAL_CALL as f64 / total_sec;

    println!("------------------------------------------------------------------------------");
    println!("压力测试完成 - 核心性能指标报表");
    println!("------------------------------------------------------------------------------");
    println!("测试配置: 总异步调用次数 = {} 次", BENCHMARK_TOTAL_CALL);
    println!("总耗时:      {:.3} 秒 ({:.3} 毫秒)", total_sec, total_ms);
    println!(
        "单次平均耗时: {:.6} 毫秒 ({:.2} 微秒)",
        avg_cost_ms,
        avg_cost_ms * 1000.0
    );
    println!("QPS(核心):   {:.0} 次/秒", qps);
    println!("------------------------------------------------------------------------------");

    // 6. 单次调用基准性能测试 - 统计极致性能（无循环叠加影响）
    // 精准采样单次detect调用的最快/最慢/平均耗时，反映组件真实单次性能
    println!("执行单次调用基准性能测试，采样极致耗时数据...");
    let mut single_cost_list = Vec::with_capacity(BASE_TEST_SAMPLE);
    for _ in 0..BASE_TEST_SAMPLE {
        let single_start = Instant::now();
        let _ = match detector::detect(&headers, test_urls, test_body_bytes).await {
            Ok(techs) => techs,
            Err(e) => {
                warn!("rswappalyzer识别失败: {}", e);
                DetectResult {
                    technologies: Vec::new(),
                }
            }
        };
        let cost_ms = single_start.elapsed().as_secs_f64() * 1000.0;
        single_cost_list.push(cost_ms);
    }

    // 基准指标计算
    let min_cost = single_cost_list
        .iter()
        .fold(f64::INFINITY, |a, &b| a.min(b));
    let max_cost = single_cost_list
        .iter()
        .fold(f64::NEG_INFINITY, |a, &b| a.max(b));
    let avg_single_cost = single_cost_list.iter().sum::<f64>() / BASE_TEST_SAMPLE as f64;

    // 基准测试结果输出
    println!("------------------------------------------------------------------------------");
    println!("基准测试完成 - 单次调用极致性能报表");
    println!("------------------------------------------------------------------------------");
    println!("采样数量: {} 次", BASE_TEST_SAMPLE);
    println!("最快耗时: {:.6} 毫秒", min_cost);
    println!("最慢耗时: {:.6} 毫秒", max_cost);
    println!("平均耗时: {:.6} 毫秒", avg_single_cost);
    println!("------------------------------------------------------------------------------");

    Ok(())
}
