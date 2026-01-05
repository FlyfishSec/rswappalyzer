use serde::Deserialize;
use serde::Serialize;

use crate::rule::core::pattern::Pattern;
use crate::rule::core::MatchCondition;
use crate::rule::core::MatchType;

// ========== 1. 通用索引规则（纯净，无任何维度特化） ==========
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommonIndexedRule {
    /// 技术名称（直接命中）
    pub tech: String,
    /// 匹配方式（Contains / Regex / Exists …）
    pub match_type: MatchType,
    /// 已预编译/清洗的模式（纯匹配逻辑）
    pub pattern: Pattern,
    /// 匹配条件（And / Or）
    pub condition: MatchCondition,
}

// ========== 2. 维度特化的索引规则（枚举封装） ==========
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScopedIndexedRule {
    /// KV 型维度（Header/Meta）：通用规则 + 键名
    KV {
        common: CommonIndexedRule,
        key: String,
    },
    /// 纯内容维度（Url/Script/Html/ScriptSrc）：仅通用规则
    Content(CommonIndexedRule),
}

// 为 ScopedIndexedRule 提供便捷方法（简化使用）
impl ScopedIndexedRule {
    /// 获取通用规则（所有维度都能拿到）
    pub fn common(&self) -> &CommonIndexedRule {
        match self {
            ScopedIndexedRule::KV { common, .. } => common,
            ScopedIndexedRule::Content(common) => common,
        }
    }

    /// 获取 KV 维度的键名（仅 KV 类型有效）
    pub fn kv_key(&self) -> Option<&str> {
        match self {
            ScopedIndexedRule::KV { key, .. } => Some(key),
            ScopedIndexedRule::Content(_) => None,
        }
    }

    /// 判断是否为 KV 型规则
    pub fn is_kv(&self) -> bool {
        matches!(self, ScopedIndexedRule::KV { .. })
    }
}