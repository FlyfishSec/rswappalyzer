use log::debug;
use rustc_hash::{FxHashMap};
use crate::{DetectionUpdater};


/// 匹配成功通用处理器 - 标准日志输出+检测结果更新
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
    debug!(
        "[{}]匹配成功 | 技术: {} | 匹配项: {} | 内容: {} | 版本: {:?} | 规则: {}",
        analyzer_type, tech_name, target_key, target_val, version, rule_desc
    );
    DetectionUpdater::update(detected, tech_name, confidence, version.clone());
}

/// 存在性匹配成功简化处理器
#[inline(always)]
pub fn handle_exists_success(
    analyzer_type: &str,
    tech_name: &str,
    target_key: &str,
    confidence: Option<u8>,
    detected: &mut FxHashMap<String, (u8, Option<String>)>,
) {
    debug!(
        "[{}]存在性匹配成功 | 技术: {} | 匹配项: {}",
        analyzer_type, tech_name, target_key
    );
    DetectionUpdater::update(detected, tech_name, confidence, None);
}
