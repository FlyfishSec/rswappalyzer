//! Wappalyzer通用逻辑
use serde_json::Value;
use std::collections::HashMap;

use crate::error::RswResult;
use crate::rule::cleaner::clean_stats::CleanStats;
use crate::rule::cleaner::pattern_processor::PatternProcessor;
use crate::rule::core::base::MatchCondition;
use crate::rule::core::pattern::{MatchType, Pattern};
use crate::rule::indexer::scope::{KeyedPattern, MatchRuleSet, MatchScope};

/// 构建列表型匹配规则集 (Url/Html/Script/ScriptSrc 通用)
#[inline(always)]
pub fn build_list_match_rule_set(
    processor: &PatternProcessor,
    value: &Option<Value>,
    stats: &mut CleanStats,
    scope_name: &str,
    scope: MatchScope,
) -> RswResult<Option<(MatchScope, MatchRuleSet)>> {
    let Some(pattern_list) =
        processor.clean_and_mark_list_pattern(value.as_ref(), stats, scope_name)?
    else {
        return Ok(None);
    };

    Ok(Some((
        scope,
        MatchRuleSet {
            condition: MatchCondition::Or,
            list_patterns: pattern_list.0,
            keyed_patterns: Vec::new(),
        },
    )))
}

/// 构建键值型匹配规则集 (Meta/Header/Cookie 通用)
#[inline(always)]
pub fn build_keyed_match_rule_set(
    processor: &PatternProcessor,
    map: &Option<&HashMap<String, Value>>,
    stats: &mut CleanStats,
    scope_name: &str,
    _scope: MatchScope,
) -> RswResult<Vec<KeyedPattern>> {
    let mut keyed_patterns = Vec::new();
    // 入参要求: Option<&HashMap<String, Value>>
    let Some(pattern_map) = processor.clean_and_mark_keyed_pattern(*map, stats, scope_name)? else {
        return Ok(keyed_patterns);
    };

    keyed_patterns = pattern_map
        .0
        .into_iter()
        .flat_map(|(k, v)| {
            v.into_iter().map(move |p| KeyedPattern {
                key: k.clone(),
                pattern: p,
            })
        })
        .collect();

    Ok(keyed_patterns)
}

/// 全局默认空Pattern
#[inline(always)]
pub fn empty_pattern() -> Pattern {
    Pattern {
        pattern: String::new(),
        match_type: MatchType::Exists, // 空Pattern默认是存在性检测
        version_template: None,
    }
}

/// 批量插入列表型规则到匹配规则MAP中
#[inline]
pub fn batch_insert_list_rules(
    match_rules: &mut HashMap<MatchScope, MatchRuleSet>,
    rules: Vec<Option<(MatchScope, MatchRuleSet)>>,
) {
    rules.into_iter().flatten().for_each(|(k, v)| {
        match_rules.insert(k, v);
    });
}
