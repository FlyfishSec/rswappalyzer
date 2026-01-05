//! 匹配作用域定义
use std::{collections::HashMap, fmt::{Display, Formatter}};
use serde::{Deserialize, Serialize};
use crate::{MatchCondition, rule::core::{Pattern, base::CachedScopeRule}};


#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize
)]
pub enum MatchScope {
    Url,
    Html,
    Js,
    Script,
    ScriptSrc,
    Header,
    Cookie,
    Meta,
    // 未来扩展：
    // Tls,
    // Banner,
}

#[derive(Debug, Clone, PartialEq)]
pub struct KeyedPattern {
    pub key: String,        // KV规则的键名（如Header的"Server"、Meta的"viewport"）
    pub pattern: Pattern,   // 具体的匹配模式
}

// 为 KeyedPattern 实现 From 特质，方便转换
impl From<(String, Pattern)> for KeyedPattern {
    fn from((key, pattern): (String, Pattern)) -> Self {
        KeyedPattern { key, pattern }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MatchRuleSet {
    pub condition: MatchCondition, // 匹配条件（And/Or）
    // 列表型规则（Url/Html/Script/ScriptSrc，无键名）
    pub list_patterns: Vec<Pattern>,
    // KV型规则（Meta/Header，带键名）
    pub keyed_patterns: Vec<KeyedPattern>,
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
                    let mut keyed: HashMap<String, Vec<Pattern>> = HashMap::new();
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


impl Display for MatchScope {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MatchScope::Url => write!(f, "url"),
            MatchScope::Html => write!(f, "html"),
            MatchScope::Js => write!(f, "js"),
            MatchScope::Script => write!(f, "script"),
            MatchScope::ScriptSrc => write!(f, "script"), // 合并到 script 统计
            MatchScope::Meta => write!(f, "meta"),
            MatchScope::Header => write!(f, "header"),
            // 若有其他 MatchScope 变体，补充对应的字符串映射
            _ => write!(f, "unknown"),
        }
    }
}
