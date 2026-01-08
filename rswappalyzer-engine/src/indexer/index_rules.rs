use crate::core::{MatchCondition, MatchType, Pattern};
use serde::{Deserialize, Serialize};

// 索引规则结构体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommonIndexedRule {
    pub tech: String,
    pub match_type: MatchType,
    pub pattern: Pattern,
    pub condition: MatchCondition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScopedIndexedRule {
    KV {
        common: CommonIndexedRule,
        key: String,
    },
    Content(CommonIndexedRule),
}

impl ScopedIndexedRule {
    pub fn common(&self) -> &CommonIndexedRule {
        match self {
            ScopedIndexedRule::KV { common, .. } => common,
            ScopedIndexedRule::Content(common) => common,
        }
    }
}

// 列表型模式（url/html/script/script_src）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternList(pub Vec<Pattern>);

/// 键值对型模式（meta/header/cookie）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMap(pub rustc_hash::FxHashMap<String, Vec<Pattern>>);

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
}