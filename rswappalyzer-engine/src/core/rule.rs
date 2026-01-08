use rustc_hash::FxHashMap;
use crate::CategoryRule;

use super::basic_info::{CategoryEntry, TechBasicInfo};
use super::enums::MatchScope;
use super::pattern::MatchRuleSet;

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

/// 核心规则库结构体，业务层统一标准结构
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RuleLibrary {
    /// 核心技术规则（技术名称 → ParsedTechRule）
    pub core_tech_map: FxHashMap<String, ParsedTechRule>,
    /// 分类规则（ID → 分类信息）
    pub category_rules: FxHashMap<u32, CategoryRule>,
}

pub type CategoryJsonRoot = FxHashMap<String, CategoryEntry>;