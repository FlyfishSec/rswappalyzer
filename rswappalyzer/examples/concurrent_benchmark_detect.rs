//! rswappalyzer fingerprint detection - Production-grade concurrent stress test
//! rswappalyzer 指纹检测 · 生产级真实并发压力测试
//! 核心特性：
//! 1. 生产级并发模型（Tokio + Semaphore）精准控制并发度
//! 2. 专业预热逻辑消除初始化干扰，保证压测数据真实有效
//! 3. 双维度性能统计（高并发吞吐 + 单调用基准延迟）
//! 4. 贴近业务场景的测试数据，压测结果可直接反映生产性能

use log::warn;
use rswappalyzer::{DetectResult, RuleConfig, TechDetector};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;

// 统一测试数据源
mod test_data1;
use test_data1 as test_data;

/// 压测核心配置 - 按需调整，生产压测建议按【并发度×批次】递增测试
const CONCURRENT_LEVEL: usize = 256;       // 核心配置：并发度(生产真实值64/128/256/512)，服务器核心数×2最佳
const WARM_UP_COUNT: u64 = 5_000;          // 预热请求数，消除初始化/缓存/分支预测影响
const BASE_TEST_SAMPLE: usize = 200;       // 单次基准测试采样量，统计真实延迟分布
const BATCH_PER_WORKER: u64 = 400;         // 每个并发工作者的测试批次
const TOTAL_REQUEST_COUNT: u64 = CONCURRENT_LEVEL as u64 * BATCH_PER_WORKER; // 总请求数

/// 生产级高并发压测主函数
/// 执行流程：
/// 1. 初始化日志和全局检测器
/// 2. 加载标准化测试数据并封装为Arc共享
/// 3. 执行并发预热消除初始化干扰
/// 4. 高并发压测并统计核心性能指标
/// 5. 单调用微基准测试统计算法性能下限
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化日志，仅输出warn级别以上，避免IO影响压测精度
    env_logger::init();

    // ========== 1. 全局检测器初始化 ==========
    // 显式初始化，禁用懒加载，贴合生产真实部署形态
    let rule_config = RuleConfig::default();
    let detector = TechDetector::new(rule_config).await?;
    let detector_arc = Arc::new(detector);

    // 输出测试配置信息
    println!("✅ rswappalyzer 生产级高并发压测开始 | 显式全局初始化完成");
    println!(
        "📋 核心配置: 并发度 = {}, 总请求数 = {}, 预热请求数 = {}",
        CONCURRENT_LEVEL, TOTAL_REQUEST_COUNT, WARM_UP_COUNT
    );
    println!("🔧 并发模型: Tokio + Semaphore | 并发窗口 = {}", CONCURRENT_LEVEL);
    println!("--------------------------------------------------------------------------------");

    // ========== 2. 加载标准化测试数据 ==========
    // 复用统一测试数据模块，避免冗余定义
    let test_headers = test_data::get_test_headers();
    let test_urls = test_data::get_test_urls();
    let test_body_bytes = test_data::get_test_html_body().as_bytes();
    
    // Arc封装共享数据，避免并发任务内存拷贝，极致性能优化
    let shared_headers = Arc::new(test_headers);
    let shared_urls = Arc::new(test_urls);
    let shared_body = Arc::new(test_body_bytes);

    // ========== 3. 并发预热逻辑 ==========
    // 消除所有初始化干扰：regex缓存/懒加载/CPU分支预测/内存页预分配
    println!("🔥 开始并发预热，消除所有初始化性能干扰...");
    let warmup_sem = Arc::new(Semaphore::new(CONCURRENT_LEVEL));
    let mut warmup_tasks = Vec::with_capacity(WARM_UP_COUNT as usize);
    
    for _ in 0..WARM_UP_COUNT {
        let permit = warmup_sem.clone().acquire_owned().await.unwrap();
        let h = shared_headers.clone();
        let u = shared_urls.clone();
        let b = shared_body.clone();
        let detector_arc_clone = Arc::clone(&detector_arc);

        warmup_tasks.push(tokio::spawn(async move {
            let _ = permit;
            let _ = detect_with_error_handling(&detector_arc_clone, &h, &u, &b).await;
        }));
    }

    // 等待预热完成
    for h in warmup_tasks {
        let _ = h.await;
    }
    
    println!("✅ 预热完成，开始高并发正式压测...");
    println!("--------------------------------------------------------------------------------");

    // ========== 4. 高并发压测执行 ==========
    let semaphore = Arc::new(Semaphore::new(CONCURRENT_LEVEL));
    let start_time = Instant::now();
    let mut task_handles = Vec::with_capacity(TOTAL_REQUEST_COUNT as usize);

    for _ in 0..TOTAL_REQUEST_COUNT {
        // 获取信号量许可，严格控制并发度
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        // Arc克隆共享数据（零成本）
        let headers = shared_headers.clone();
        let urls = shared_urls.clone();
        let body = shared_body.clone();
        let detector_arc_clone = Arc::clone(&detector_arc);

        // 生成异步任务，由Tokio调度器管理
        task_handles.push(tokio::spawn(async move {
            let _permit_guard = permit; // 任务完成自动释放许可
            let _result = detect_with_error_handling(&detector_arc_clone, &headers, &urls, &body).await;
        }));
    }

    // 等待所有压测任务完成
    for h in task_handles {
        let _ = h.await;
    }

    // ========== 5. 核心性能指标计算 ==========
    let total_elapsed = start_time.elapsed();
    let total_sec = total_elapsed.as_secs_f64();
    let total_ms = total_sec * 1000.0;
    let avg_cost_ms = total_ms / TOTAL_REQUEST_COUNT as f64;
    let real_qps = TOTAL_REQUEST_COUNT as f64 / total_sec;
    let req_per_ms = TOTAL_REQUEST_COUNT as f64 / total_ms;

    // 输出高并发性能报表
    println!("📊 真实高并发压测完成 - 核心性能指标报表");
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

    // ========== 6. 单调用微基准测试 ==========
    // 统计纯函数级性能下限，无并发/调度/锁干扰
    println!("📈 开始执行【无并发干扰】单次调用微基准测试...");
    let mut single_cost_list = Vec::with_capacity(BASE_TEST_SAMPLE);
    
    for _ in 0..BASE_TEST_SAMPLE {
        let single_start = Instant::now();
        let detector_arc_clone = Arc::clone(&detector_arc);
        let _ = detect_with_error_handling(&detector_arc_clone, &shared_headers, &shared_urls, &shared_body).await;
        let cost_ms = single_start.elapsed().as_secs_f64() * 1000.0;
        single_cost_list.push(cost_ms);
    }

    // 计算基准指标
    let min_cost = single_cost_list.iter().fold(f64::INFINITY, |a, &b| a.min(b));
    let max_cost = single_cost_list.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));
    let avg_single_cost = single_cost_list.iter().sum::<f64>() / BASE_TEST_SAMPLE as f64;

    // 输出基准测试报表
    println!("✅ 单次调用微基准测试完成 - 纯函数级性能下限");
    println!("--------------------------------------------------------------------------------");
    println!("采样数量: {} 次 (无并发/调度/锁干扰)", BASE_TEST_SAMPLE);
    println!("最快耗时: {:.6} 毫秒", min_cost);
    println!("最慢耗时: {:.6} 毫秒", max_cost);
    println!("平均耗时: {:.6} 毫秒", avg_single_cost);
    println!("--------------------------------------------------------------------------------");

    Ok(())
}

/// 封装业务级检测逻辑+错误处理
/// 特性：
/// 1. 内联优化，减少函数调用开销
/// 2. 统一错误处理，返回空结果而非panic
/// 3. 与生产代码1:1对齐，保证压测真实性
#[inline(always)]
async fn detect_with_error_handling(
    detector: &TechDetector,
    headers: &Arc<http::header::HeaderMap>,
    urls: &Arc<&[&str]>,
    body: &Arc<&[u8]>,
) -> DetectResult {
    match detector.detect(headers, urls, &body) {
        Ok(techs) => techs,
        Err(e) => {
            warn!("❌ rswappalyzer识别失败: {}", e);
            DetectResult {
                technologies: Vec::new(),
                implies: None,
            }
        }
    }
}
