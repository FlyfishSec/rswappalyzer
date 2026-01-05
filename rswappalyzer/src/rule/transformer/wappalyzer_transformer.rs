//! Wappalyzer Go 原始规则转换器
use log::{debug, warn};
use serde_json::Value;
use std::collections::HashMap;

use crate::error::{RswResult, RswappalyzerError};
use crate::rule::cleaner::clean_stats::CleanStats;
use crate::rule::cleaner::pattern_processor::PatternProcessor;
use crate::rule::core::RuleLibrary;
use crate::rule::core::base::{MatchCondition, TechBasicInfo};
use crate::rule::core::category_rule::{CategoryRule, get_default_categories};
use crate::rule::core::parsed_rule::ParsedTechRule;
use crate::rule::indexer::scope::{MatchRuleSet, MatchScope};
use crate::rule::source::wappalyzer_go::original::{
    WappalyzerOriginalRuleLibrary, WappalyzerOriginalTechRule,
};
use crate::rule::transformer::RuleTransformer;

// 引入公共方法
use super::wappalyzer_common::{
    batch_insert_list_rules, build_keyed_match_rule_set, build_list_match_rule_set,
};

/// Wappalyzer Go 规则转换器
#[derive(Debug)]
pub struct WappalyzerGoTransformer {
    original_lib: WappalyzerOriginalRuleLibrary,
    pattern_processor: PatternProcessor,
}

impl WappalyzerGoTransformer {
    /// 创建转换器实例
    #[inline(always)]
    pub fn new(original_lib: WappalyzerOriginalRuleLibrary) -> Self {
        Self {
            original_lib,
            pattern_processor: PatternProcessor::default(),
        }
    }

    /// 转换分类规则
    #[inline]
    fn transform_categories(&self) -> HashMap<u32, CategoryRule> {
        let mut categories = get_default_categories();
        for (id, original_cat) in &self.original_lib.categories {
            categories.insert(
                *id,
                CategoryRule {
                    id: *id,
                    name: original_cat.name.clone(),
                    priority: original_cat.priority,
                },
            );
        }
        categories
    }

    /// 转换单条技术规则
    fn transform_tech_rule(
        &self,
        tech_name: &str,
        original_tech: &WappalyzerOriginalTechRule,
        stats: &mut CleanStats,
    ) -> RswResult<ParsedTechRule> {
        // 构建基础信息
        let basic = TechBasicInfo {
            tech_name: Some(tech_name.to_string()),
            category_ids: original_tech.category_ids.clone(),
            implies: Self::implies_value_to_vec(&original_tech.implies),

            #[cfg(feature = "full-meta")]
            description: original_tech.description,
            #[cfg(feature = "full-meta")]
            website: original_tech.website,
            #[cfg(feature = "full-meta")]
            icon: original_tech.icon,
            #[cfg(feature = "full-meta")]
            cpe: original_tech.cpe,
            #[cfg(feature = "full-meta")]
            saas: original_tech.saas,
            #[cfg(feature = "full-meta")]
            pricing: original_tech.pricing,
            ..TechBasicInfo::default()
        };
        // 批量处理列表型规则
        let mut match_rules = HashMap::new();
        let list_rules = vec![
            build_list_match_rule_set(
                &self.pattern_processor,
                &original_tech.url,
                stats,
                "url",
                MatchScope::Url,
            )?,
            build_list_match_rule_set(
                &self.pattern_processor,
                &original_tech.html,
                stats,
                "html",
                MatchScope::Html,
            )?,
            build_list_match_rule_set(
                &self.pattern_processor,
                &original_tech.scripts,
                stats,
                "script",
                MatchScope::Script,
            )?,
            build_list_match_rule_set(
                &self.pattern_processor,
                &original_tech.script_src,
                stats,
                "script_src",
                MatchScope::ScriptSrc,
            )?,
        ];
        batch_insert_list_rules(&mut match_rules, list_rules);

        // 处理Meta规则
        if let Some(meta_map) = &original_tech.meta {
            let keyed_patterns = build_keyed_match_rule_set(
                &self.pattern_processor,
                &Some(meta_map),
                stats,
                "meta",
                MatchScope::Meta,
            )?;
            if !keyed_patterns.is_empty() {
                match_rules.insert(
                    MatchScope::Meta,
                    MatchRuleSet {
                        condition: MatchCondition::Or,
                        list_patterns: Vec::new(),
                        keyed_patterns,
                    },
                );
            }
        }

        // 处理Header 规则 - 独立作用域 MatchScope::Header
        if let Some(header_map) = &original_tech.headers {
            let header_keyed_patterns = build_keyed_match_rule_set(
                &self.pattern_processor,
                &Some(header_map),
                stats,
                "header",
                MatchScope::Header,
            )?;
            if !header_keyed_patterns.is_empty() {
                match_rules.insert(
                    MatchScope::Header,
                    MatchRuleSet {
                        condition: MatchCondition::Or,
                        list_patterns: Vec::new(),
                        keyed_patterns: header_keyed_patterns,
                    },
                );
            }
        }

        // 处理Cookie 规则 - 独立作用域 MatchScope::Cookie
        if let Some(cookie_map) = &original_tech.cookies {
            let cookie_keyed_patterns = build_keyed_match_rule_set(
                &self.pattern_processor,
                &Some(cookie_map),
                stats,
                "cookie",
                MatchScope::Cookie,
            )?;
            if !cookie_keyed_patterns.is_empty() {
                match_rules.insert(
                    MatchScope::Cookie,
                    MatchRuleSet {
                        condition: MatchCondition::Or,
                        list_patterns: Vec::new(),
                        keyed_patterns: cookie_keyed_patterns,
                    },
                );
            }
        }

        // 处理Js 规则 - 独立作用域 MatchScope::Js
        if let Some(js_map) = &original_tech.js {
            let js_keyed_patterns = build_keyed_match_rule_set(
                &self.pattern_processor,
                &Some(js_map),
                stats,
                "js",
                MatchScope::Js,
            )?;
            if !js_keyed_patterns.is_empty() {
                match_rules.insert(
                    MatchScope::Js,
                    MatchRuleSet {
                        condition: MatchCondition::Or,
                        list_patterns: Vec::new(),
                        keyed_patterns: js_keyed_patterns,
                    },
                );
            }
        }

        Ok(ParsedTechRule { basic, match_rules })
    }

    // serde_json::Value 转 Vec<String>，兼容单字符串/数组两种格式
    fn implies_value_to_vec(implies_val: &Option<Value>) -> Option<Vec<String>> {
        let Some(val) = implies_val else {
            return None;
        };
        let mut res = Vec::new();
        match val {
            // 情况1: 原始值是数组 ["a", "b"]
            Value::Array(arr) => {
                for item in arr {
                    if let Value::String(s) = item {
                        let s = s.trim().to_string();
                        if !s.is_empty() {
                            res.push(s);
                        }
                    }
                }
            }
            // 情况2: 原始值是单个字符串 "a"
            Value::String(s) => {
                let s = s.trim().to_string();
                if !s.is_empty() {
                    res.push(s);
                }
            }
            // 其他非法格式（数字/布尔/对象）直接忽略
            _ => {}
        }
        // 有内容则返回Some，无内容返回None，保持语义一致
        if res.is_empty() { None } else { Some(res) }
    }
}

impl RuleTransformer for WappalyzerGoTransformer {
    #[inline]
    fn transform(&self) -> RswResult<RuleLibrary> {
        let mut stats = CleanStats::default();
        let mut core_tech_map = HashMap::new();

        for (tech_name, original_tech) in &self.original_lib.technologies {
            match self.transform_tech_rule(tech_name, original_tech, &mut stats) {
                Ok(parsed_tech) => {
                    core_tech_map.insert(tech_name.to_string(), parsed_tech);
                }
                Err(e) => {
                    warn!("转换技术规则 [{}] 失败：{}", tech_name, e);
                    continue;
                }
            }
        }

        let category_rules = self.transform_categories();

        debug!(
            "Wappalyzer规则转换完成：有效技术规则 {} 条，分类规则 {} 条",
            core_tech_map.len(),
            category_rules.len()
        );
        debug!("转换统计：{:?}", stats);

        if core_tech_map.is_empty() {
            return Err(RswappalyzerError::RuleLoadError(
                "Wappalyzer原始规则转换后无有效技术规则".to_string(),
            ));
        }

        Ok(RuleLibrary {
            core_tech_map,
            category_rules,
        })
    }
}
