//! 单条模式结构

use serde::{Deserialize, Serialize};

/// 匹配类型枚举
/// 用于标记每条模式的匹配方式，方便扫描时直接使用
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MatchType {
    Contains,
    StartsWith,
    Regex,
    Exists, // 存在性检测（仅用于 headers/meta 的空值场景）
}

impl Default for MatchType {
    fn default() -> Self {
        MatchType::Regex
    }
}

/// 单条预处理模式
/// 1. `pattern` 已移除 PCRE 分隔符，且已修复错误
/// 2. `match_type` 表示匹配方式
/// 3. `version_template` 可提取版本信息（如 1.2.3）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Pattern {
    pub pattern: String,
    pub match_type: MatchType,
    pub version_template: Option<String>,
}
