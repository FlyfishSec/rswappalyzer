//! Embedded rule detection demonstration for rswappalyzer
//! rswappalyzer 嵌入式规则指纹识别演示程序
//! 功能说明：
//! 1. 演示嵌入式固化规则库的加载与使用
//! 2. 展示完整的Web指纹识别流程（Header/URL/HTML多维度检测）
//! 3. 包含性能耗时统计与结构化JSON结果输出
//! 
//! 运行命令：
//! cargo run --example detect_demo --features="embedded-rules"

use std::error::Error;
#[cfg(feature = "embedded-rules")]
use env_logger::{Builder, Env, Target};
#[cfg(feature = "embedded-rules")]
use rswappalyzer::{RuleConfig, RuleOrigin, TechDetector};
#[cfg(feature = "embedded-rules")]
use serde_json::to_string_pretty;
#[cfg(feature = "embedded-rules")]
use std::{
    time::{Instant},
};

// 统一测试数据源
mod test_data3;
use test_data3 as test_data;

/// 嵌入式规则指纹识别演示主函数
/// 执行流程：
/// 1. 初始化结构化日志系统
/// 2. 配置嵌入式规则并初始化检测器
/// 3. 加载标准化测试数据
/// 4. 执行多维度指纹检测（含性能统计）
/// 5. 输出格式化检测结果
#[cfg(feature = "embedded-rules")]
fn main() -> Result<(), Box<dyn Error>> {
    // ========== 1. 日志系统初始化 ==========
    Builder::from_env(Env::default().default_filter_or("debug"))
        .target(Target::Stdout)
        .init();

    // ========== 2. 初始化嵌入式规则检测器 ==========
    // 配置嵌入式规则源（使用编译期固化的规则库）
    let rule_config = RuleConfig {
        origin: RuleOrigin::Embedded,
        ..RuleConfig::default()
    };
    
    // 初始化检测器（嵌入式规则无需异步加载）
    let detector = TechDetector::with_embedded_rules(rule_config)?;
    println!("✅ 指纹检测器初始化完成 | 使用内置规则库");

    // ========== 3. 加载标准化测试数据 ==========
    let test_headers = test_data::get_test_headers();    // HTTP Header数据
    let test_urls = test_data::get_test_urls();          // 目标URL数组
    let test_html = test_data::get_test_html_body();     // HTML响应体内容

    // ========== 4. 执行指纹检测（含高精度性能统计） ==========
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

    // ========== 5. 输出结构化检测结果 ==========
    println!("\n======================================= 检测结果 =======================================");
    println!("✅ 指纹检测完成 | 总耗时: {:.3} 毫秒", detect_duration_ms);
    println!("========================================================================================");
    
    // 格式化输出JSON结果（便于解析和可视化）
    let result_json = to_string_pretty(&detect_result)?;
    println!("📊 检测结果（结构化JSON）:\n{}", result_json);

    Ok(())
}

#[cfg(not(feature = "embedded-rules"))]
fn main() -> Result<(), Box<dyn Error>> {
    Err("❌ 请启用 embedded-rules 特性后运行：cargo run --example detect_demo --features=\"embedded-rules\"".into())
}