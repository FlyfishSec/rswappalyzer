//! rswappalyzer fingerprint detection - Professional stress & benchmark testing
//! rswappalyzer 指纹检测 专业压力测试 & 基准性能测试
//! 核心特性：
//! 1. 标准化调用流程（全局初始化 + 异步detect检测）
//! 2. 预热机制消除初始化干扰，保证压测数据真实性
//! 3. 双维度性能统计（高并发吞吐 + 单次调用基准）
//! 4. 行业标准性能指标输出（QPS/平均耗时/微秒级精度）
//! 
//! 运行命令: 
//! cargo run --example baseline_benchmark_detect --features embedded-rules --release

use log::warn;
use rswappalyzer::{DetectResult, RuleConfig, detector, init_global_detector};
use std::time::Instant;

// 统一测试数据源
mod test_data;

/// 压测核心配置项 - 按需调整，建议循序渐进 1万 → 10万 → 100万
const BENCHMARK_TOTAL_CALL: u64 = 10000;        // 正式压测总调用次数
const BENCHMARK_WARM_UP_CALL: u64 = 1000;       // 预热调用次数，消除懒加载/初始化影响
const BENCHMARK_PROGRESS_STEP: u64 = 10000;     // 压测进度打印步长，避免IO干扰
const BASE_TEST_SAMPLE: usize = 100;            // 单次基准测试采样量

/// 专业压力测试主函数
/// 执行流程：
/// 1. 初始化日志和全局检测器
/// 2. 加载标准化测试数据
/// 3. 执行预热调用消除初始化干扰
/// 4. 高并发异步压测并统计核心性能指标
/// 5. 单次调用基准测试统计算法性能下限
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化日志，仅输出warn级别以上，避免IO影响压测精度
    env_logger::init();

    // ========== 1. 全局检测器初始化 ==========
    // 与生产代码1:1对齐，使用默认配置，全局唯一实例
    let rule_config = RuleConfig::default();
    init_global_detector(rule_config).await?;

    // 输出测试基础信息
    println!("✅ rswappalyzer 指纹检测 压力测试开始");
    println!("🔧 初始化状态: 全局检测器已加载 | 规则库: 嵌入式固化 | 编译模式: Release(全优化)");
    println!(
        "📋 测试配置: 预热次数 = {}, 压测总次数 = {}",
        BENCHMARK_WARM_UP_CALL, BENCHMARK_TOTAL_CALL
    );
    println!("------------------------------------------------------------------------------");

    // ========== 2. 加载标准化测试数据 ==========
    // 复用统一测试数据模块，保证测试数据一致性
    let test_headers = test_data::get_test_headers();
    let test_urls = test_data::get_test_urls();
    let test_body_bytes = test_data::get_test_html_body().as_bytes();

    // ========== 3. 执行预热调用 ==========
    // 关键优化：消除初始化影响（懒加载/正则缓存/内存预分配/CPU分支预测）
    println!("🔥 执行预热调用，消除初始化性能干扰...");
    for _ in 0..BENCHMARK_WARM_UP_CALL {
        let _ = detector::detect(&test_headers, test_urls, test_body_bytes).await;
    }
    println!("✅ 预热完成，开始正式异步压测...");
    println!("------------------------------------------------------------------------------");

    // ========== 4. 正式高并发异步压测 ==========
    let start_time = Instant::now();
    
    for index in 0..BENCHMARK_TOTAL_CALL {
        // 执行指纹检测并处理错误
        let _ = detect_with_error_handling(&test_headers, test_urls, test_body_bytes).await;

        // 按步长打印进度，避免高频IO导致压测数据失真
        if (index + 1) % BENCHMARK_PROGRESS_STEP == 0 {
            println!(
                "📊 压测进度: 已完成 {} / {} 次指纹检测调用",
                index + 1,
                BENCHMARK_TOTAL_CALL
            );
        }
    }
    
    let total_elapsed = start_time.elapsed();

    // ========== 5. 核心性能指标计算 & 专业报表输出 ==========
    let total_sec = total_elapsed.as_secs_f64();
    let total_ms = total_sec * 1000.0;
    let avg_cost_ms = total_ms / BENCHMARK_TOTAL_CALL as f64;
    let qps = BENCHMARK_TOTAL_CALL as f64 / total_sec;

    println!("------------------------------------------------------------------------------");
    println!("📈 压力测试完成 - 核心性能指标报表");
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

    // ========== 6. 单次调用基准性能测试 ==========
    // 统计无干扰的单次调用性能，反映算法真实下限
    println!("🔍 执行单次调用基准性能测试，采样极致耗时数据...");
    let mut single_cost_list = Vec::with_capacity(BASE_TEST_SAMPLE);
    
    for _ in 0..BASE_TEST_SAMPLE {
        let single_start = Instant::now();
        let _ = detect_with_error_handling(&test_headers, test_urls, test_body_bytes).await;
        let cost_ms = single_start.elapsed().as_secs_f64() * 1000.0;
        single_cost_list.push(cost_ms);
    }

    // 计算基准指标
    let min_cost = single_cost_list.iter().fold(f64::INFINITY, |a, &b| a.min(b));
    let max_cost = single_cost_list.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));
    let avg_single_cost = single_cost_list.iter().sum::<f64>() / BASE_TEST_SAMPLE as f64;

    // 输出基准测试报表
    println!("------------------------------------------------------------------------------");
    println!("🎯 基准测试完成 - 单次调用极致性能报表");
    println!("------------------------------------------------------------------------------");
    println!("采样数量: {} 次", BASE_TEST_SAMPLE);
    println!("最快耗时: {:.6} 毫秒", min_cost);
    println!("最慢耗时: {:.6} 毫秒", max_cost);
    println!("平均耗时: {:.6} 毫秒", avg_single_cost);
    println!("------------------------------------------------------------------------------");

    Ok(())
}

/// 封装检测逻辑+错误处理
/// 特性：
/// 1. 统一错误处理策略，避免panic
/// 2. 内联优化，减少函数调用开销
/// 3. 与生产代码逻辑对齐，保证压测真实性
#[inline(always)]
async fn detect_with_error_handling(
    headers: &http::header::HeaderMap,
    urls: &[&str],
    body: &[u8],
) -> DetectResult {
    match detector::detect(headers, urls, body).await {
        Ok(techs) => techs,
        Err(e) => {
            warn!("❌ rswappalyzer识别失败: {}", e);
            DetectResult {
                technologies: Vec::new(),
            }
        }
    }
}