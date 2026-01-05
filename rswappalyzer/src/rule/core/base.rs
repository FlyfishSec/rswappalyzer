//! 规则通用基础模型
use std::{collections::HashMap};
use serde::{Deserialize, Serialize};
use crate::{TechMatcher, rule::{core::{CategoryRule, PatternList, PatternMap, parsed_rule::ParsedTechRule, pattern::Pattern}, indexer::scope::MatchScope, source::{fingerprinthub::original::FingerprintHubOriginalMatcher, wappalyzer_go::original::WappalyzerOriginalRuleLibrary}}};


/// 原始匹配规则集合（接收 parser 输出的原始数据）
#[derive(Debug, Clone)]
pub struct RawMatchSet {
    pub url_patterns: Option<PatternList>,
    pub html_patterns: Option<PatternList>,
    pub script_patterns: Option<PatternList>,
    pub script_src_patterns: Option<PatternList>,
    pub meta_pattern_map: Option<PatternMap>,
    pub header_pattern_map: Option<PatternMap>,
    pub cookie_pattern_map: Option<PatternMap>,
    pub js_pattern_map: Option<PatternMap>,
}

/// 原始规则库（Raw）
/// 直接存储 Wappalyzer / FingerprintHub 等 JSON / 原始源规则
/// 仅用于重新清理或比对，不用于扫描匹配
pub struct RuleRawLibrary {
    pub wappalyzer: Option<WappalyzerOriginalRuleLibrary>,
    // pub fingerprint_hub: Option<FingerprintHubOriginalRuleLibrary>,
    // 可扩展其他原始规则源
}

/// 清理后的核心规则库（Core）
/// 存储统一清理后的技术规则集合
/// 是扫描匹配前的核心数据结构，可序列化缓存（msgpack）
#[derive(Debug, Clone, Default)]
pub struct RuleLibrary {
    /// 核心技术规则（技术名称 → ParsedTechRule）
    pub core_tech_map: HashMap<String, ParsedTechRule>,
    /// 分类规则（ID → 分类信息）
    pub category_rules: HashMap<u32, CategoryRule>,
}

// 作用域级别的缓存规则，包含条件+模式，无冗余
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedScopeRule {
    pub condition: MatchCondition,
    // 列表型规则（Url/Html/Script/ScriptSrc）
    pub list_patterns: Option<Vec<Pattern>>,
    // KV型规则（Header/Meta），直接存储键值对，无需拼接字符串
    pub keyed_patterns: Option<HashMap<String, Vec<Pattern>>>,
}

/// 规则库缓存结构（仅包含运行期所需的稳定数据）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedTechRule {
    pub basic: TechBasicInfo, // 技术基础信息（含 tech_name）
    // 按作用域聚合规则，1个作用域 = 1个条目，避免重复存储 condition
    pub rules: HashMap<MatchScope, CachedScopeRule>,
}
// #[derive(Serialize, Deserialize)]
// pub struct CachedTechRule {
//     pub basic: TechBasicInfo,
//     pub rules: Vec<CachedRuleEntry>,
// }

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

/// 技术基础信息，仅存储描述/分类等元信息，无匹配规则
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct TechBasicInfo {
    pub tech_name: Option<String>,
    pub category_ids: Vec<u32>,
    #[serde(default)]
    pub implies: Option<Vec<String>>,
    //pub implies: Option<serde_json::Value>,

    // 非规则必须字段
    #[cfg(feature = "full-meta")]
    pub cpe: Option<String>,
    #[cfg(feature = "full-meta")]
    pub description: Option<String>,
    #[cfg(feature = "full-meta")]
    pub website: Option<String>,
    #[cfg(feature = "full-meta")]
    pub icon: Option<String>,
    #[cfg(feature = "full-meta")]
    pub saas: Option<bool>,
    #[cfg(feature = "full-meta")]
    pub pricing: Option<Vec<String>>,
}

/// 匹配条件枚举
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MatchCondition {
    And,
    #[default]
    Or,
}

/// 匹配类型枚举
/// 用于标记每条模式的匹配方式，方便扫描时直接使用，无需二次解析
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MatchType {
    /// 模式出现在目标文本中即可匹配
    Contains,
    /// 目标文本以模式开头即可匹配
    StartsWith,
    /// 正则匹配
    Regex,
    /// 存在性检测（仅用于 headers/meta 的空值场景）
    Exists,
}

impl Default for MatchType {
    fn default() -> Self {
        MatchType::Regex
    }
}

/// 从 FingerprintHub 原始匹配器转换为统一 TechMatcher
impl TryFrom<&FingerprintHubOriginalMatcher> for TechMatcher {
    type Error = crate::error::RswappalyzerError;

    fn try_from(original: &FingerprintHubOriginalMatcher) -> Result<Self, Self::Error> {
        match original {
            FingerprintHubOriginalMatcher::Word {
                header_name,
                words,
                case_insensitive,
                condition,
            } => Ok(TechMatcher::Word {
                header_name: header_name.clone(),
                words: words.clone(),
                case_insensitive: *case_insensitive,
                condition: condition.clone(),
            }),
            FingerprintHubOriginalMatcher::Regex {
                header_name,
                regex,
                case_insensitive,
                condition,
            } => Ok(TechMatcher::Regex {
                header_name: header_name.clone(),
                regex: regex.clone(),
                case_insensitive: *case_insensitive,
                condition: condition.clone(),
            }),
        }
    }
}