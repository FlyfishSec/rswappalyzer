// benchmark_detect_concurrent.rs
// rswappalyzer 指纹检测 · 生产级真实并发压力测试
use log::warn;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use rswappalyzer::{DetectResult, RuleConfig, detector, init_global_detector};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;

/// 压测核心配置 - 按需调整，生产压测建议按【并发度×批次】递增测试
const CONCURRENT_LEVEL: usize = 256; // 核心配置：并发度(生产真实值64/128/256/512)，服务器核心数×2最佳
const WARM_UP_COUNT: u64 = 5_000; // 预热请求数，消除初始化/缓存/分支预测影响
const BASE_TEST_SAMPLE: usize = 200; // 单次基准测试采样量，统计真实延迟分布
const BATCH_PER_WORKER: u64 = 400;
const TOTAL_REQUEST_COUNT: u64 = CONCURRENT_LEVEL as u64 * BATCH_PER_WORKER; // 总请求数，建议=CONCURRENT_LEVEL × 400 以上

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化日志，适配业务的warn错误输出，无额外性能损耗
    env_logger::init();

    // 1. 显式全局初始化检测器 - 禁用隐式懒加载，基准测试可对比，无重构风险
    // 与业务代码保持一致，全局仅初始化一次，内部单例+Arc+锁，贴合生产真实形态
    let rule_config = RuleConfig::default();
    init_global_detector(rule_config).await?;
    println!("rswappalyzer 生产级高并发压测开始 | 显式全局初始化完成");
    println!(
        "核心配置: 并发度 = {}, 总请求数 = {}, 预热请求数 = {}",
        CONCURRENT_LEVEL, TOTAL_REQUEST_COUNT, WARM_UP_COUNT
    );
    println!("并发模型: Tokio + Semaphore | 并发窗口 = {}", CONCURRENT_LEVEL);
    println!("--------------------------------------------------------------------------------");

    // 2. 构造生产级测试样本 - 无冗余Clone，专业写法，可选开启随机化样本
    // 基准样本：贴近真实业务的请求头+HTML响应体，包含完整指纹特征
    let test_headers = build_prod_headers();
    let test_urls = &[]; // 与业务代码完全一致，传空数组
    let test_body_bytes = build_prod_html_body().as_bytes();
    // 封装为Arc只读共享，避免并发任务中重复内存拷贝，极致性能优化
    let shared_headers = Arc::new(test_headers);
    let shared_body = Arc::new(test_body_bytes);

    // 3. 专业预热逻辑 - 你认可的核心优点，完整保留并优化
    // 消除所有干扰项：regex缓存加载/once_cell懒初始化/CPU分支预测/内存页预分配/全局锁预热
    // 预热阶段同样使用并发模型，模拟真实预热，不是串行预热
    println!("开始并发预热，消除所有初始化性能干扰...");
    let warmup_sem = Arc::new(Semaphore::new(CONCURRENT_LEVEL));
    let mut warmup_tasks = Vec::with_capacity(WARM_UP_COUNT as usize);
    for _ in 0..WARM_UP_COUNT {
        let permit = warmup_sem.clone().acquire_owned().await.unwrap();
        let h = shared_headers.clone();
        let b = shared_body.clone();
        warmup_tasks.push(tokio::spawn(async move {
            let _ = permit;
            let _ = detect_with_error_handling(&h, test_urls, &b).await;
        }));
    }

    for h in warmup_tasks {
        let _ = h.await;
    }

    println!("预热完成，开始高并发正式压测...");
    println!("--------------------------------------------------------------------------------");

    // 4. ✅ 核心改造：生产级真实高并发压测逻辑（完全采纳你的指正）
    // 关键点：Tokio spawn异步任务 + Semaphore并发度限流 + Arc共享只读数据
    // 模拟生产真实场景：请求竞争、任务调度、锁竞争、正则缓存并发读写、Arc引用计数竞争
    // 无任何打印/IO操作，彻底消除调度干扰，压测数据100%真实有效
    let semaphore = Arc::new(Semaphore::new(CONCURRENT_LEVEL));
    let start_time = Instant::now();
    let mut task_handles = Vec::with_capacity(TOTAL_REQUEST_COUNT as usize);

    for _ in 0..TOTAL_REQUEST_COUNT {
        // 获取信号量许可，严格控制并发度上限
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        // Arc克隆共享数据，零成本，无内存拷贝
        let headers = shared_headers.clone();
        let body = shared_body.clone();

        // Spawn独立异步任务，由Tokio调度器调度，模拟真实请求分发
        task_handles.push(tokio::spawn(async move {
            let _permit_guard = permit; // 任务完成后自动释放许可，复用并发槽位
            let _result = detect_with_error_handling(&headers, test_urls, &body).await;
        }));
    }

    // 等待所有并发任务执行完成，无任何中间输出
    for h in task_handles {
        let _ = h.await;
    }

    let total_elapsed = start_time.elapsed();

    // 5. 生产级核心性能指标计算 - 真实有效，无乐观假象
    // 指标均为行业标准，QPS是真实吞吐能力，不是 1/单次耗时 的理论值
    let total_sec = total_elapsed.as_secs_f64();
    let total_ms = total_sec * 1000.0;
    let avg_cost_ms = total_ms / TOTAL_REQUEST_COUNT as f64;
    let real_qps = TOTAL_REQUEST_COUNT as f64 / total_sec;
    let req_per_ms = TOTAL_REQUEST_COUNT as f64 / total_ms;

    // 输出纯净的性能报表，无冗余内容
    println!("真实高并发压测完成 - 核心性能指标报表");
    println!("--------------------------------------------------------------------------------");
    println!(
        "测试配置: 并发度 = {}, 总请求数 = {} 次",
        CONCURRENT_LEVEL, TOTAL_REQUEST_COUNT
    );
    println!("总耗时:      {:.3} 秒 ({:.3} 毫秒)", total_sec, total_ms);
    println!(
        "单次平均耗时: {:.6} 毫秒 ({:.2} 微秒)",
        avg_cost_ms,
        avg_cost_ms * 1000.0
    );
    println!("真实QPS:     {:.0} 次/秒 (生产核心指标)", real_qps);
    println!("毫秒吞吐:    {:.2} 次/毫秒", req_per_ms);
    println!("--------------------------------------------------------------------------------");

    // 6. 保留你认可的：单次调用微基准测试（纯函数级极限延迟，无并发干扰）
    // 统计 P-min/P-max/P-avg，反映detect本身的算法性能下限，无调度/锁/竞争影响
    println!("开始执行【无并发干扰】单次调用微基准测试...");
    let mut single_cost_list = Vec::with_capacity(BASE_TEST_SAMPLE);
    for _ in 0..BASE_TEST_SAMPLE {
        let single_start = Instant::now();
        let _ = detect_with_error_handling(&shared_headers, test_urls, &shared_body).await;
        let cost_ms = single_start.elapsed().as_secs_f64() * 1000.0;
        single_cost_list.push(cost_ms);
    }

    // 计算基准指标
    let min_cost = single_cost_list
        .iter()
        .fold(f64::INFINITY, |a, &b| a.min(b));
    let max_cost = single_cost_list
        .iter()
        .fold(f64::NEG_INFINITY, |a, &b| a.max(b));
    let avg_single_cost = single_cost_list.iter().sum::<f64>() / BASE_TEST_SAMPLE as f64;

    // 输出基准报表
    println!("单次调用微基准测试完成 - 纯函数级性能下限");
    println!("--------------------------------------------------------------------------------");
    println!("采样数量: {} 次 (无并发/调度/锁干扰)", BASE_TEST_SAMPLE);
    println!("最快耗时: {:.6} 毫秒", min_cost);
    println!("最慢耗时: {:.6} 毫秒", max_cost);
    println!("平均耗时: {:.6} 毫秒", avg_single_cost);
    println!("--------------------------------------------------------------------------------");

    Ok(())
}

/// 封装业务代码1:1的检测逻辑+错误处理，全局复用，无冗余
/// 百分百保留你的业务逻辑：match捕获错误 + warn日志 + 兜底空DetectResult
#[inline(always)]
async fn detect_with_error_handling(
    headers: &HeaderMap,
    urls: &[&str],
    body: &[u8],
) -> DetectResult {
    match detector::detect(headers, urls, body).await {
        Ok(techs) => techs,
        Err(e) => {
            warn!("rswappalyzer识别失败: {}", e);
            DetectResult {
                technologies: Vec::new(),
            }
        }
    }
}

/// 构建生产级真实请求头，贴近业务场景，无冗余
fn build_prod_headers() -> HeaderMap {
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
    headers
}

/// 构建生产级真实HTML响应体，包含完整指纹特征，贴近业务场景
fn build_prod_html_body() -> &'static str {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=0">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <title>Production Business Page</title>
    <link rel="stylesheet" href="/css/iconfont.min.css" />
    <script src="/js/jquery-1.9.1.min.js"></script>
    <script src="/js/gVerify.js"></script>
    <script src="/js/vue2.7.min.js"></script>
</head>
<body>
    <div class="container"><div class="banner"><img src="/images/logo.png" /></div></div>
    <script>window.onload = function(){ var app = new Vue({ el: '.container' }); };</script>
</body>
</html>"#
}

// #0.2.0
// #架构升级，易于扩展多源
// #核心引擎优化，放弃初始全量正则编译，引入literal剪枝逻辑，预过滤无关规则，大幅降低资源占用，毫秒级启动，毫秒级精准匹配!
// #移除Tracing,减轻依赖包

// #支持dom、cookies匹配
// #在Windows 4核 可稳定提供约 90 QPS 的吞吐能力

// rswappalyzer 生产级高并发压测开始 | 显式全局初始化完成
// 核心配置: 并发度 = 256, 总请求数 = 102400, 预热请求数 = 5000
// 并发模型: Tokio + Semaphore | 并发窗口 = 256
// --------------------------------------------------------------------------------
// 开始并发预热，消除所有初始化性能干扰...
// 预热完成，开始高并发正式压测...
// --------------------------------------------------------------------------------
// 真实高并发压测完成 - 核心性能指标报表
// --------------------------------------------------------------------------------
// 测试配置: 并发度 = 256, 总请求数 = 102400 次
// 总耗时:      500.613 秒 (500613.263 毫秒)
// 单次平均耗时: 4.888801 毫秒 (4888.80 微秒)
// 真实QPS:     205 次/秒 (生产核心指标)
// 毫秒吞吐:    0.20 次/毫秒
// --------------------------------------------------------------------------------
// 开始执行【无并发干扰】单次调用微基准测试...
// 单次调用微基准测试完成 - 纯函数级性能下限
// --------------------------------------------------------------------------------
// 采样数量: 200 次 (无并发/调度/锁干扰)
// 最快耗时: 13.404000 毫秒
// 最慢耗时: 19.540500 毫秒
// 平均耗时: 15.793368 毫秒
// --------------------------------------------------------------------------------
// --------------------------------------------------------------------------------
// 检测耗时: 27.991 ms
// --------------------------------------------------------------------------------
// {
//   "technologies": [
//     {
//       "name": "jQuery",
//       "version": "1.9.1",
//       "categories": [
//         "JavaScript libraries"
//       ],
//       "confidence": 100
//     },
//     {
//       "name": "Microsoft ASP.NET",
//       "version": null,
//       "categories": [
//         "Web frameworks"
//       ],
//       "confidence": 100
//     }
//   ]
// }