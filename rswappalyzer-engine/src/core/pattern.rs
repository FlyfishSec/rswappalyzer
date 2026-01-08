use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use crate::{MatchScope, core::cached_rule::CachedScopeRule};

use super::enums::{MatchCondition, MatchType};

/// 单条预处理模式
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Pattern {
    pub pattern: String,
    pub match_type: MatchType,
    pub version_template: Option<String>,
}

/// KV规则结构体（Header/Meta/Cookie专用）
#[derive(Debug, Clone, PartialEq)]
pub struct KeyedPattern {
    pub key: String,      // KV规则的键名
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

impl MatchRuleSet {
    pub fn new() -> Self {
        Self::default()
    }

    // 添加列表型规则
    pub fn add_list_pattern(&mut self, pattern: Pattern) {
        self.list_patterns.push(pattern);
    }

    // 添加KV型规则
    pub fn add_keyed_pattern(&mut self, keyed_pattern: KeyedPattern) {
        self.keyed_patterns.push(keyed_pattern);
    }

    /// 新建指定条件的 MatchRuleSet
    pub fn with_condition(condition: MatchCondition) -> Self {
        Self {
            condition,
            list_patterns: Vec::new(),
            keyed_patterns: Vec::new(),
        }
    }

    // 从缓存结构转换为运行时结构（无字符串拆分）
    pub fn from_cached(scope: &MatchScope, cached: CachedScopeRule) -> Self {
        let mut rule_set = Self::with_condition(cached.condition);
        match scope {
            MatchScope::Url | MatchScope::Html | MatchScope::Script | MatchScope::ScriptSrc => {
                if let Some(patterns) = cached.list_patterns {
                    rule_set.list_patterns = patterns;
                }
            }
            MatchScope::Header | MatchScope::Cookie | MatchScope::Meta | MatchScope::Js=> {
                if let Some(keyed) = cached.keyed_patterns {
                    // 用 flat_map 替代 map + flatten，减少一层 collect
                    rule_set.keyed_patterns = keyed.into_iter()
                        .flat_map(|(k, v)| v.into_iter().map(move |p| KeyedPattern::from((k.clone(), p))))
                        .collect();
                }
            }
        }
        rule_set
    }

    // 从运行时结构转换为缓存结构（无字符串拼接）
    pub fn to_cached(&self, scope: &MatchScope) -> CachedScopeRule {
        let mut cached = CachedScopeRule {
            condition: self.condition.clone(),
            list_patterns: None,
            keyed_patterns: None,
        };
        match scope {
            MatchScope::Url | MatchScope::Html | MatchScope::Script | MatchScope::ScriptSrc => {
                if !self.list_patterns.is_empty() {
                    cached.list_patterns = Some(self.list_patterns.clone());
                }
            }
            MatchScope::Header | MatchScope::Cookie | MatchScope::Meta | MatchScope::Js => {
                if !self.keyed_patterns.is_empty() {
                    // 显式指定 HashMap 类型
                    let mut keyed: FxHashMap<String, Vec<Pattern>> = FxHashMap::default();
                    for kp in &self.keyed_patterns {
                        keyed.entry(kp.key.clone())
                            .or_default()
                            .push(kp.pattern.clone());
                    }
                    cached.keyed_patterns = Some(keyed);
                }
            }
        }
        cached
    }
}
