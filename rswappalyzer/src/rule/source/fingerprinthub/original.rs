//! FingerprintHub 专属规则模型
//! 仅存放 FingerprintHub 规则的原始结构

use serde::{Deserialize, Serialize};

use crate::{MatchCondition, rule::core::TechMatcher};



/// FingerprintHub 原始匹配器
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FingerprintHubOriginalMatcher {
    Word {
        header_name: Option<String>,
        words: Vec<String>,
        case_insensitive: bool,
        condition: MatchCondition,
    },
    Regex {
        header_name: Option<String>,
        regex: Vec<String>,
        case_insensitive: bool,
        condition: MatchCondition,
    },
}

/// FingerprintHub 规则的 info 嵌套对象
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintHubRuleInfo {
    pub name: String,
    pub author: Option<String>,
    pub tags: Option<String>,
    pub severity: Option<String>,
    pub metadata: Option<serde_json::Value>,

    pub category: Option<Vec<String>>,
    pub description: Option<String>,
    pub website: Option<String>,
    pub cpe: Option<String>,
}

/// FingerprintHub 规则的 http 匹配器嵌套对象
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintHubHttpMatcher {
    #[serde(rename = "type")] // JSON 里是 "type"，Rust 关键字冲突，需要重命名
    pub matcher_type: String, // 匹配器类型："word" 或 "regex"
    pub words: Option<Vec<String>>, // word 类型才有该字段
    pub regex: Option<Vec<String>>, // regex 类型才有该字段
    #[serde(default)] // 没有该字段时默认 false
    pub case_insensitive: bool,
    #[serde(default, rename = "condition")] // 匹配条件，默认 And
    pub condition: MatchCondition,
}

/// FingerprintHub 规则的 http 嵌套对象
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintHubHttpRule {
    pub method: Option<String>,
    pub path: Vec<String>,
    pub matchers: Vec<FingerprintHubHttpMatcher>, // 原始匹配器列表
}

/// FingerprintHub 原始技术规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintHubOriginalTechRule {
    #[serde(rename = "id")] // JSON 里是 "id"，映射到 Rust 的 name 字段
    pub name: String,
    pub info: FingerprintHubRuleInfo, // JSON 嵌套的 info 对象
    pub http: Vec<FingerprintHubHttpRule>, // JSON 嵌套的 http 数组
    // 原有字段：JSON 中不存在，暂时注释或改为 Option
    // pub description: Option<String>, // JSON 中没有，保持 Option
    // pub website: Option<String>, // JSON 中没有，保持 Option
    // #[serde(default)] // 没有 categories 字段时默认空数组
    // pub categories: Vec<u32>,
    // pub icon: Option<String>, // JSON 中没有，保持 Option
    // 原有 body_matchers/header_matchers：JSON 中不存在，后续从 http.matchers 转换
    #[serde(skip_deserializing, skip_serializing)] // 不参与 JSON 解析/序列化
    pub body_matchers: Vec<FingerprintHubOriginalMatcher>,
    #[serde(skip_deserializing, skip_serializing)] // 不参与 JSON 解析/序列化
    pub header_matchers: Vec<FingerprintHubOriginalMatcher>,
}

/// FingerprintHub 原始规则列表
pub type FingerprintHubOriginalRuleList = Vec<FingerprintHubOriginalTechRule>;

/// 按匹配位置分类的 FH 匹配器（通用技术规则复用）
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TechMatchers {
    pub body: Vec<TechMatcher>,
    pub header: Vec<TechMatcher>,
}