use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::{
    Matcher, compiled::{LiteralId, LiteralInterner}
};

// 纯静态的匹配规则描述体
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MatcherSpec {
    Contains(LiteralId),
    Exists,
    Regex {
        pattern: String,
        case_insensitive: bool,
    },
}

// 运行时匹配器 转换方法
impl MatcherSpec {
    #[inline]
    pub fn to_matcher(&self) -> Matcher {
        match self {
            MatcherSpec::Contains(lid) => Matcher::Contains(*lid),
            MatcherSpec::Exists => Matcher::Exists,
            MatcherSpec::Regex {
                pattern,
                case_insensitive,
            } => Matcher::LazyRegex {
                pattern: Arc::new(pattern.clone()),
                case_insensitive: *case_insensitive,
            },
        }
    }

    // #[inline]
    // pub fn to_matcher(&self, cache: Arc<RegexCache>) -> Matcher {
    //     match self {
    //         MatcherSpec::Contains(lid) => Matcher::Contains(*lid),
    //         MatcherSpec::Exists => Matcher::Exists,
    //         MatcherSpec::Regex {
    //             pattern,
    //             case_insensitive,
    //         } => Matcher::LazyRegex {
    //             pattern: Arc::new(pattern.clone()),
    //             case_insensitive: *case_insensitive,
    //             cache,
    //         },
    //     }
    // }
}

/// 匹配准入网关 - 流水线式设计（核心重构点）
/// 每个阶段都是可选字段，执行顺序固定：token检查 → 字面量检查 → 结构any检查
/// 所有阶段均为“可选但顺序不可变”，自然实现短路执行
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MatchGate {
    /// 阶段1：原始必现字面量剪枝
    #[serde(skip)]
    pub require_literals: Option<Vec<String>>,
    pub require_literal_ids: Option<Vec<LiteralId>>,
    /// 阶段2：结构前置剪枝（并集字面量）
    #[serde(skip)]
    pub require_any_literals: Option<Vec<String>>,
    pub require_any_literal_ids: Option<Vec<LiteralId>>,
}

impl MatchGate {
    /// 为字符串版MatchGate补全ID字段
    pub fn fill_ids(self, literal_interner: &LiteralInterner) -> Self {
        let mut gate = self;

        // 补全最小证据字面量ID
        if let Some(literals) = &gate.require_literals {
            gate.require_literal_ids = Some(
                literals
                    .iter()
                    .filter_map(|s| literal_interner.get_id(s))
                    .collect(),
            );
        }

        // Any字面量ID
        if let Some(any_list) = &gate.require_any_literals {
            gate.require_any_literal_ids = Some(
                any_list
                    .iter()
                    .filter_map(|s| literal_interner.get_id(s))
                    .collect(),
            );
        }

        gate
    }
}

/// 结构前置条件 ≠ 最小证据，是正则匹配的「准入门槛」，缺失则直接跳过正则执行
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub enum StructuralPrereq {
    /// 必须包含指定子串 (精准命中单一特征)
    RequiresSubstring(String),
    /// 必须包含任意一个子串 (命中OR分支的任意特征，适配(?:A|B|C|D)结构)
    RequiresAny(Vec<String>),
    /// 无结构前置条件
    #[default]
    None,
}

/// 作用域枚举
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scope {
    Url,
    Html,
    Script,
    Header,
    Meta,
    Cookie,
}
