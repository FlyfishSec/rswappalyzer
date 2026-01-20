//! 通用分析工具模块
//! 核心能力：
//! 1. 编译期可控的高性能日志处理（零运行时开销）
//! 2. 零拷贝集合类型转换（String → &str）
//! 3. AnalyzerInput 扩展接口（批量转换集合）

use rswappalyzer_engine::log_format::preview_compact;
use rustc_hash::{FxHashMap};

use crate::DetectionUpdater;

/// 日志内容最大展示长度，超长自动UTF8安全截断
const MAX_CONTENT_LEN: usize = 80;

// ======================== 编译期日志配置 ========================
/// 编译期日志开关：debug模式启用，release模式完全失效（零开销）
#[cfg(debug_assertions)]
const ENABLE_DEBUG_LOG: bool = true;
#[cfg(not(debug_assertions))]
const ENABLE_DEBUG_LOG: bool = false;

// ======================== 日志宏封装 ========================
/// 全局调试日志宏（编译期控制）
/// release模式下展开为空，无任何运行时开销；debug模式下转发至log::debug
#[macro_export]
macro_rules! debug_log {
    ($($arg:tt)*) => {
        if ENABLE_DEBUG_LOG {
            log::debug!($($arg)*);
        }
    };
}

/// 匹配成功日志处理器（完整版）
/// 记录匹配详情并更新检测结果，debug模式下输出结构化日志
/// 
/// # 参数
/// - `analyzer_type`: 分析器类型（如HTML/Header/Cookie）
/// - `tech_name`: 匹配到的技术名称
/// - `target_key`: 匹配目标键（如HTML_CONTENT/SCRIPT_SRC）
/// - `target_val`: 匹配目标值（原始内容）
/// - `version`: 提取的版本信息
/// - `confidence`: 匹配置信度
/// - `rule_desc`: 匹配规则描述
/// - `detected`: 检测结果映射表（输出参数）
#[inline(always)]
pub fn handle_match_success(
    analyzer_type: &str,
    tech_name: &str,
    target_key: &str,
    target_val: &str,
    version: &Option<String>,
    confidence: Option<u8>,
    rule_desc: &str,
    detected: &mut FxHashMap<String, (u8, Option<String>)>,
) {
    // Debug模式输出结构化日志（零分配内容预览）
    if ENABLE_DEBUG_LOG {
        debug_log!(
            "[{}] Match success | Tech: {} | Key: {} | Preview: {} | Version: {:?} | Rule: {}",
            analyzer_type,
            tech_name,
            target_key,
            preview_compact(target_val, MAX_CONTENT_LEN),
            version,
            rule_desc
        );
    }

    // 更新检测结果
    DetectionUpdater::update(detected, tech_name, confidence, version.clone());
}

/// 存在性匹配成功处理器（简化版）
/// 记录存在性匹配结果并更新检测结果，仅输出核心日志信息
/// 
/// # 参数
/// - `analyzer_type`: 分析器类型
/// - `tech_name`: 匹配到的技术名称
/// - `target_key`: 匹配目标键
/// - `confidence`: 匹配置信度
/// - `detected`: 检测结果映射表（输出参数）
#[inline(always)]
pub fn handle_exists_success(
    analyzer_type: &str,
    tech_name: &str,
    target_key: &str,
    confidence: Option<u8>,
    detected: &mut FxHashMap<String, (u8, Option<String>)>,
) {
    debug_log!(
        "[{}] Exists match success | Tech: {} | Key: {}",
        analyzer_type,
        tech_name,
        target_key
    );
    DetectionUpdater::update(detected, tech_name, confidence, None);
}

// ======================== 集合转换工具 ========================
// 零拷贝转换：&FxHashSet<&String> → FxHashSet<&str>
// 
// # 生命周期
// - `'a`: 绑定输入集合中引用的生命周期
// 
// # 参数
// - `set`: 待转换的 &String 引用集合
// 
// # 返回值
// 等价的 &str 引用集合（零拷贝）
// pub fn convert_string_ref_set_to_str_set<'a>(set: &FxHashSet<&'a String>) -> FxHashSet<&'a str> {
//     set.iter().map(|&s| s.as_str()).collect()
// }

// 零拷贝转换：&FxHashSet<String> → FxHashSet<&str>
// 
// # 生命周期
// - `'a`: 绑定输入集合的引用生命周期
// 
// # 参数
// - `set`: 待转换的 String 集合
// 
// # 返回值
// 等价的 &str 引用集合（零拷贝）
// pub fn convert_string_set_to_str_set<'a>(set: &'a FxHashSet<String>) -> FxHashSet<&'a str> {
//     set.iter().map(|s| s.as_str()).collect()
// }

// AnalyzerInput 扩展接口：批量转换集合为 &str 类型
// 
// 为所有实现 AnalyzerInput 的类型提供批量转换方法，
// 一次性获取所有 hit 集合的 &str 版本（零拷贝）
// pub trait AnalyzerInputStrExt: super::AnalyzerInput {
//     /// 批量转换所有 hit 集合为 &str 类型
//     /// 
//     /// # 返回值
//     /// (literals_hit_lc, any_hit_lc, contains_hit_lc) 的 &str 集合
//     fn get_all_str_sets(&self) -> (FxHashSet<&str>, FxHashSet<&str>, FxHashSet<&str>) {
//         let literals_hit_lc = convert_string_set_to_str_set(self.get_literals_hit_lc());
//         let any_hit_lc = convert_string_set_to_str_set(self.get_any_hit_lc());
//         let contains_hit_lc = convert_string_set_to_str_set(self.get_contains_hit_lc());
//         (literals_hit_lc, any_hit_lc, contains_hit_lc)
//     }
// }

// // 为所有实现 AnalyzerInput 的类型自动实现扩展接口
// impl<T: super::AnalyzerInput> AnalyzerInputStrExt for T {}