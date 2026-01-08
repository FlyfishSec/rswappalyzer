//! Local rule detection demonstration for rswappalyzer
//! rswappalyzer 本地规则指纹识别演示程序
//! 功能说明：
//! 1. 演示本地Wappalyzer规则库加载流程
//! 2. 展示多维度Web指纹识别能力（Header/URL/HTML检测）
//! 3. 包含性能耗时统计与结构化JSON结果输出
//! 
//! 运行命令：
//! cargo run --example local_detect_demo

use env_logger::{Builder, Env, Target};
use rswappalyzer::{RuleConfig, TechDetector};
use serde_json::to_string_pretty;
use std::{
    error::Error,
    time::{Instant},
};

// 统一测试数据源
mod test_data;

/// 异步主函数 - 本地规则指纹识别演示入口
/// 执行流程：
/// 1. 初始化结构化日志系统
/// 2. 配置本地规则加载参数
/// 3. 初始化TechDetector检测器
/// 4. 加载标准化测试数据并执行指纹检测
/// 5. 输出检测结果（含精准耗时统计与格式化JSON）
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // ========== 1. 日志系统初始化 ==========
    // 配置日志级别为INFO，输出到标准输出，启用结构化日志格式
    Builder::from_env(Env::default().default_filter_or("debug"))
        .target(Target::Stdout)
        .init();

    // ========== 2. 本地规则配置 ==========
    // 本地规则文件路径（支持相对/绝对路径）
    const LOCAL_RULE_FILE: &str = "rswappalyzer_rules.json";
    
    // 构建本地规则配置（禁用自动更新，提升本地规则加载效率）
    let rule_config = RuleConfig::local_file(LOCAL_RULE_FILE);

    // ========== 3. 初始化指纹检测器 ==========
    // 异步初始化检测器（加载并解析本地规则文件）
    let detector = TechDetector::new(rule_config).await?;

    // ========== 4. 加载标准化测试数据（复用test_data模块） ==========
    // 从统一测试数据模块获取标准化输入，避免代码冗余
    let test_headers = test_data::get_test_headers();    // HTTP Header数据
    let test_urls = test_data::get_test_urls();          // 目标URL数组
    let test_html = test_data::get_test_html_body();     // HTML响应体内容

    // ========== 5. 执行指纹检测（含高精度性能统计） ==========
    let start_instant = Instant::now();
    
    // 执行多维度指纹检测（Header + URL + HTML）
    let detect_result = detector.detect(
        &test_headers, 
        test_urls, 
        test_html.as_bytes()
    )?;
    
    // 计算检测耗时（精确到毫秒级，保留三位小数）
    let detect_duration = start_instant.elapsed();
    let detect_duration_ms = detect_duration.as_secs_f64() * 1000.0;

    // ========== 6. 输出结构化检测结果 ==========
    println!("\n======================================= 检测结果 =======================================");
    println!("✅ 本地规则指纹检测完成 | 总耗时: {:.3} 毫秒", detect_duration_ms);
    println!("========================================================================================");
    
    // 格式化输出JSON结果（便于后续解析和可视化）
    let result_json = to_string_pretty(&detect_result)?;
    println!("📊 检测结果（结构化JSON）:\n{}", result_json);

    Ok(())
}
