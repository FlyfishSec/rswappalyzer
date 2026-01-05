//! 规则转换器模块
//! 负责将不同源的原始规则（Wappalyzer/FingerprintHub）转换为统一的核心规则库（RuleLibrary）
//! 解耦解析层与核心规则层，实现多源标准化

pub mod wappalyzer_converter;
// 后续可扩展 fingerprinthub_converter

use crate::RuleLibrary;
use crate::error::{RswResult, RswappalyzerError};
use crate::rule::core::{CategoryRule, ParsedTechRule, PatternList, TechBasicInfo};
use crate::rule::core::{MatchCondition};
use crate::rule::cleaner::pattern_processor::PatternProcessor;
use crate::rule::index::scope::{MatchRuleSet, MatchScope};

/// 通用规则转换 trait
pub trait RuleConverter {
    /// 将原始规则转换为统一的核心规则库
    fn convert_to_core(&self) -> RswResult<RuleLibrary>;
}

/// 处理 Wappalyzer 单个原始技术规则转换
pub fn convert_wappalyzer_tech_rule(
    tech_name: &str,
    original: &crate::rule::source::wappalyzer_go::original::WappalyzerOriginalTechRule,
    pattern_processor: &PatternProcessor
) -> RswResult<ParsedTechRule> {
    let mut match_rules = std::collections::HashMap::new();
    
    // 1. 构建技术基础信息
    let basic = TechBasicInfo {
        description: original.description.clone(),
        website: original.website.clone(),
        category_ids: original.category_ids.clone(),
        icon: original.icon.clone(),
        cpe: original.cpe.clone(),
        saas: original.saas,
        pricing: original.pricing.clone(),
        tech_name: Some(tech_name.to_string()),
        implies: original.implies.clone(),
    };

    // 2. 处理 URL 规则
    if let Some(url_value) = &original.url {
        let patterns = pattern_processor.process_wappalyzer_pattern_value(url_value, MatchScope::Url)?;
        if !patterns.is_empty() {
            match_rules.insert(
                MatchScope::Url,
                MatchRuleSet {
                    condition: MatchCondition::Or, // Wappalyzer 默认 OR 条件
                    list_patterns: Some(PatternList(patterns)),
                    keyed_patterns: None,
                }
            );
        }
    }

    // 3. 处理 HTML 规则
    if let Some(html_value) = &original.html {
        let patterns = pattern_processor.process_wappalyzer_pattern_value(html_value, MatchScope::Html)?;
        if !patterns.is_empty() {
            match_rules.insert(
                MatchScope::Html,
                MatchRuleSet {
                    condition: MatchCondition::Or,
                    list_patterns: Some(PatternList(patterns)),
                    keyed_patterns: None,
                }
            );
        }
    }

    // 4. 处理 Script 规则
    if let Some(scripts_value) = &original.scripts {
        let patterns = pattern_processor.process_wappalyzer_pattern_value(scripts_value, MatchScope::Script)?;
        if !patterns.is_empty() {
            match_rules.insert(
                MatchScope::Script,
                MatchRuleSet {
                    condition: MatchCondition::Or,
                    list_patterns: Some(PatternList(patterns)),
                    keyed_patterns: None,
                }
            );
        }
    }

    // 5. 处理 ScriptSrc 规则
    if let Some(script_src_value) = &original.script_src {
        let patterns = pattern_processor.process_wappalyzer_pattern_value(script_src_value, MatchScope::ScriptSrc)?;
        if !patterns.is_empty() {
            match_rules.insert(
                MatchScope::ScriptSrc,
                MatchRuleSet {
                    condition: MatchCondition::Or,
                    list_patterns: Some(PatternList(patterns)),
                    keyed_patterns: None,
                }
            );
        }
    }

    // 6. 处理 Meta 规则（KV 类型）
    if let Some(meta_map) = &original.meta {
        let mut keyed_patterns = std::collections::HashMap::new();
        for (meta_name, meta_value) in meta_map {
            let patterns = pattern_processor.process_wappalyzer_pattern_value(meta_value, MatchScope::Meta)?;
            if !patterns.is_empty() {
                keyed_patterns.insert(meta_name.clone(), patterns);
            }
        }
        if !keyed_patterns.is_empty() {
            match_rules.insert(
                MatchScope::Meta,
                MatchRuleSet {
                    condition: MatchCondition::Or,
                    list_patterns: None,
                    keyed_patterns: Some(keyed_patterns),
                }
            );
        }
    }

    // 7. 处理 Header 规则（KV 类型）
    if let Some(header_map) = &original.headers {
        let mut keyed_patterns = std::collections::HashMap::new();
        for (header_name, header_value) in header_map {
            let patterns = pattern_processor.process_wappalyzer_pattern_value(header_value, MatchScope::Header)?;
            if !patterns.is_empty() {
                keyed_patterns.insert(header_name.clone(), patterns);
            }
        }
        if !keyed_patterns.is_empty() {
            match_rules.insert(
                MatchScope::Header,
                MatchRuleSet {
                    condition: MatchCondition::Or,
                    list_patterns: None,
                    keyed_patterns: Some(keyed_patterns),
                }
            );
        }
    }

    Ok(ParsedTechRule { basic, match_rules })
}

/// 转换 Wappalyzer 原始分类规则
pub fn convert_wappalyzer_categories(
    original_categories: &std::collections::HashMap<u32, crate::rule::source::wappalyzer_go::original::WappalyzerOriginalCategory>
) -> std::collections::HashMap<u32, CategoryRule> {
    let mut categories = std::collections::HashMap::new();
    for (id, original_cat) in original_categories {
        categories.insert(*id, CategoryRule {
            name: original_cat.name.clone(),
            priority: original_cat.priority,
            id: *id,
        });
    }
    categories
}