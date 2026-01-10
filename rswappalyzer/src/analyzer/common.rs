//! 生产级日志处理模块 - 零堆分配、极致性能
//! 核心特性：
//! 1. 编译期日志控制（debug/release模式差异化）
//! 2. 零堆分配：空白字符折叠+UTF8安全截断，无任何堆内存分配
//! 3. 高性能：内联优化、FxHashMap适配、无冗余计算
//! 4. 易接入：模块化设计，可直接集成到任意Rust项目

use rswappalyzer_engine::log_format::preview_compact;
use rustc_hash::FxHashMap;

use crate::DetectionUpdater;


/// 日志内容最大展示长度，超长自动截断
const MAX_CONTENT_LEN: usize = 80;

// ======================== 编译期配置 ========================
/// 编译期断言：debug模式启用日志，release模式日志完全失效(零开销)
#[cfg(debug_assertions)]
const ENABLE_DEBUG_LOG: bool = true;
#[cfg(not(debug_assertions))]
const ENABLE_DEBUG_LOG: bool = false;

// ======================== 日志宏封装 ========================
/// 全局日志宏 - 统一入口，编译期控制开关
/// 特性：release模式下完全为空，零运行时开销
#[macro_export]
macro_rules! debug_log {
    ($($arg:tt)*) => {
        if ENABLE_DEBUG_LOG {
            log::debug!($($arg)*);
        }
    };
}

/// 匹配成功日志处理器（完整版）
/// 接入点：你的系统中匹配成功时调用此函数即可
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
    // 仅debug模式处理日志，release模式跳过（零开销）
    if ENABLE_DEBUG_LOG {
        debug_log!(
            "[{}] Match success | Tech: {} | Key: {} | Preview: {} | Version: {:?} | Rule: {}",
            analyzer_type,
            tech_name,
            target_key,
            preview_compact(target_val, MAX_CONTENT_LEN), // 零分配折叠+截断
            version,
            rule_desc
        );
    }

    // 更新检测结果（高性能FxHashMap）
    DetectionUpdater::update(detected, tech_name, confidence, version.clone());
}

/// 存在性匹配成功处理器（简化版）
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
    dbg!(&detected);
    DetectionUpdater::update(detected, tech_name, confidence, None);
}
