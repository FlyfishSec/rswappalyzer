use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

use crate::{MatchCondition, MatchScope, Pattern, TechBasicInfo};



// 作用域级别的缓存规则，包含条件+模式，无冗余
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedScopeRule {
    pub condition: MatchCondition,
    // 列表型规则（Url/Html/Script/ScriptSrc）
    pub list_patterns: Option<Vec<Pattern>>,
    // KV型规则（Header/Meta），直接存储键值对，无需拼接字符串
    pub keyed_patterns: Option<FxHashMap<String, Vec<Pattern>>>,
}

/// 规则库缓存结构（仅包含运行期所需的稳定数据）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedTechRule {
    pub basic: TechBasicInfo, // 技术基础信息（含 tech_name）
    // 按作用域聚合规则，1个作用域 = 1个条目，避免重复存储 condition
    pub rules: FxHashMap<MatchScope, CachedScopeRule>,
}

/// 缓存用：单条规则项（稳定、可序列化）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedRuleEntry {
    /// 匹配作用域（url / html / header / meta 等）
    pub scope: MatchScope,
    /// AND / OR
    pub condition: MatchCondition,
    /// 具体模式列表
    pub patterns: Vec<Pattern>,
}
