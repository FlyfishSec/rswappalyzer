use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
//use std::collections::HashMap;
use std::fmt::{Display, Formatter};

/// 核心规则库结构体，业务层统一标准结构
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RuleLibrary {
    /// 核心技术规则（技术名称 → ParsedTechRule）
    pub core_tech_map: FxHashMap<String, ParsedTechRule>,
    /// 分类规则（ID → 分类信息）
    pub category_rules: FxHashMap<u32, CategoryRule>,
}

/// 分类规则定义（通用，多源解析后统一结构）
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct CategoryRule {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub priority: Option<u32>,
    #[serde(default)]
    pub id: u32,
}

/// 匹配作用域枚举，定义所有支持的检测维度
#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum MatchScope {
    Url,
    Html,
    Js,
    Script,
    ScriptSrc,
    Header,
    Cookie,
    Meta,
}

impl Display for MatchScope {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MatchScope::Url => write!(f, "url"),
            MatchScope::Html => write!(f, "html"),
            MatchScope::Js => write!(f, "html"),
            MatchScope::Script => write!(f, "script"),
            MatchScope::ScriptSrc => write!(f, "script"), // 合并到 script 统计
            MatchScope::Meta => write!(f, "meta"),
            MatchScope::Header => write!(f, "header"),
            MatchScope::Cookie => write!(f, "cookie"),
        }
    }
}

/// 匹配类型枚举，标记每条模式的匹配方式
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

/// 匹配条件枚举
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MatchCondition {
    And,
    #[default]
    Or,
}

/// 单条预处理模式
/// 1. pattern 已移除 PCRE 分隔符，且已修复错误
/// 2. match_type 表示匹配方式
/// 3. version_template 可提取版本信息（如 1.2.3）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Pattern {
    pub pattern: String,
    pub match_type: MatchType,
    pub version_template: Option<String>,
}

/// KV规则结构体（Header/Meta/Cookie专用）
#[derive(Debug, Clone, PartialEq)]
pub struct KeyedPattern {
    pub key: String,      // KV规则的键名（如Header的"Server"、Meta的"viewport"）
    pub pattern: Pattern, // 具体的匹配模式
}

impl From<(String, Pattern)> for KeyedPattern {
    fn from((key, pattern): (String, Pattern)) -> Self {
        KeyedPattern { key, pattern }
    }
}

/// 匹配规则集合，按作用域聚合的规则组
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MatchRuleSet {
    pub condition: MatchCondition,         // 匹配条件（And/Or）
    pub list_patterns: Vec<Pattern>,       // 列表型规则（Url/Html/Script/ScriptSrc）
    pub keyed_patterns: Vec<KeyedPattern>, // KV型规则（Meta/Header/Cookie）
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

/// 解析后的标准化技术规则
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ParsedTechRule {
    pub basic: TechBasicInfo,
    pub match_rules: FxHashMap<MatchScope, MatchRuleSet>,
}

impl From<&ParsedTechRule> for TechBasicInfo {
    fn from(rule: &ParsedTechRule) -> Self {
        rule.basic.clone()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryEntry {
    #[serde(default)] // 缺groups → 空数组 []
    pub groups: Vec<u32>,
    pub name: String,
    #[serde(default)]
    pub priority: u8,
}

pub type CategoryJsonRoot = FxHashMap<String, CategoryEntry>;
