//! 解析阶段技术规则
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::{MatchCondition, rule::indexer::scope::{MatchRuleSet, MatchScope}};
use super::{TechBasicInfo};


#[derive(Debug, Clone, Default)]
pub struct ParsedTechRule {
    // 技术基础信息
    pub basic: TechBasicInfo,
    // 统一后的匹配规则
    pub match_rules: HashMap<MatchScope, MatchRuleSet>,
}

impl From<&ParsedTechRule> for TechBasicInfo {
    fn from(rule: &ParsedTechRule) -> Self {
        rule.basic.clone()
    }
}


/// 按匹配位置分类的匹配器
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TechMatchers {
    pub body: Vec<TechMatcher>, // body 匹配器
    pub header: Vec<TechMatcher>, // header 匹配器
}

/// Fingerprinthub匹配器
/// 统一技术匹配器（中间模型，承接原始规则与编译器）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TechMatcher {
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
