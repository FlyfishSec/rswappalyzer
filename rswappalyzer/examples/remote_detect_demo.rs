//! Remote rule detection demonstration for rswappalyzer
//! rswappalyzer 远程规则指纹识别演示程序
//! 功能说明：
//! 1. 演示远程Wappalyzer规则库加载流程
//! 2. 展示完整的Web指纹识别能力（Header/URL/HTML多维度检测）
//! 3. 包含性能耗时统计与结构化结果输出
//! 
//! 运行命令：
//! cargo run --example remote_detect_demo --features="remote-loader"

use env_logger::{Builder, Env, Target};
use rswappalyzer::{RetryPolicy, RuleConfig, TechDetector};
use serde_json::to_string_pretty;
use std::{error::Error, path::PathBuf, time::{Duration, Instant}};

// 统一测试数据源
mod test_data3;

/// 异步主函数 - 远程规则指纹识别演示入口
/// 执行流程：
/// 1. 初始化日志系统
/// 2. 配置远程规则加载参数
/// 3. 初始化TechDetector检测器
/// 4. 加载测试数据并执行指纹检测
/// 5. 输出检测结果（含耗时统计与结构化JSON）
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // ========== 1. 日志系统初始化 ==========
    // 配置日志级别为DEBUG，输出到标准输出，启用结构化日志
    Builder::from_env(Env::default().default_filter_or("debug"))
        .target(Target::Stdout)
        .init();

    // ========== 2. 远程规则配置 ==========
    // Wappalyzer规则库远程地址（标准化的指纹规则源）
    const RULE_REMOTE_URL: &str = "https://ghfast.top/raw.githubusercontent.com/projectdiscovery/wappalyzergo/refs/heads/main/fingerprints_data.json";
    
    // 构建远程规则配置
    let mut rule_config = RuleConfig::remote_custom(
        RULE_REMOTE_URL,                // 远程规则URL
        Duration::from_secs(10),        // 请求超时时间
        RetryPolicy::Times(2)           // 重试策略（失败重试2次）
    );
    
    // 不检查更新
    rule_config.options.check_update = false;

    // 自定义规则缓存目录
    rule_config.options.cache_dir = PathBuf::from("./custom_cache");

    // ========== 3. 初始化指纹检测器 ==========
    // 异步初始化检测器（自动下载/缓存/解析规则）
    let detector = TechDetector::new(rule_config).await?;

    // ========== 4. 加载测试数据 ==========
    // 从测试模块获取标准化测试输入
    let test_headers = test_data::get_test_headers();    // HTTP Header数据
    let test_urls = test_data::get_test_urls();          // URL路径数据
    let test_html = test_data::get_test_html_body();     // HTML页面内容

    // ========== 5. 执行指纹检测（含性能统计） ==========
    let start_instant = Instant::now();
    
    // 执行多维度指纹检测
    let detect_result = detector.detect(
        &test_headers, 
        test_urls, 
        test_html.as_bytes()
    )?;
    
    // 计算检测耗时（精确到毫秒级，保留三位小数）
    let detect_duration = start_instant.elapsed();
    let detect_duration_ms = detect_duration.as_secs_f64() * 1000.0;

    // ========== 6. 输出检测结果 ==========
    println!("\n======================================= 检测结果 =======================================");
    println!("✅ 指纹检测完成 | 总耗时: {:.3} 毫秒", detect_duration_ms);
    println!("========================================================================================");
    
    // 格式化输出JSON结果（便于解析和查看）
    let result_json = to_string_pretty(&detect_result)?;
    println!("📊 检测结果（结构化JSON）:\n{}", result_json);

    Ok(())
}