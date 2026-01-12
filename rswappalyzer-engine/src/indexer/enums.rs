use std::sync::Arc;

use rustc_hash::FxHashSet;
use serde::{Deserialize, Serialize};

use crate::{Matcher, min_evidence_checker, safe_lower::contains_ignore_ascii_case};

// 纯静态的匹配规则描述体
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MatcherSpec {
    Contains(String),
    Exists,
    Regex {
        pattern: String,
        case_insensitive: bool,
    },
}

// 运行时匹配器 转换方法
impl MatcherSpec {
    #[inline(always)]
    pub fn to_matcher(&self) -> Matcher {
        match self {
            MatcherSpec::Contains(s) => Matcher::Contains(Arc::new(s.clone())),
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
}

/// 匹配准入网关 - 流水线式设计（核心重构点）
/// 每个阶段都是可选字段，执行顺序固定：token检查 → 字面量检查 → 结构any检查
/// 所有阶段均为“可选但顺序不可变”，自然实现短路执行
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MatchGate {
    /// 阶段1：最小证据剪枝（交集token）- 可选
    pub require_tokens: Option<FxHashSet<String>>,
    /// 阶段2：原始必现字面量剪枝 - 可选（兜底必现证据）
    pub require_literal: Option<String>,
    /// 阶段3：结构前置剪枝（并集字面量）- 可选
    pub require_any_literal: Option<Vec<String>>,
}

impl MatchGate {
    /// 运行期剪枝校验核心方法 - 严格按阶段顺序执行，自然短路
    /// 核心逻辑：
    /// 1. 阶段1：token检查（有则执行，失败直接返回false）
    /// 2. 阶段2：字面量检查（有则执行，失败直接返回false）
    /// 3. 阶段3：结构any检查（有则执行，失败直接返回false）
    /// 4. 所有阶段通过/无阶段 → 返回true
    #[inline(always)]
    pub fn check(&self, input: &str, input_tokens: &FxHashSet<String>) -> bool {
        // 阶段1：token交集检查（最高优先级）- 有则执行，短路
        if let Some(tokens) = &self.require_tokens {
            if !tokens.iter().all(|t| input_tokens.contains(t)) {
                return false;
            }
        }

        // 阶段2：原始必现字面量检查（兜底）- 有则执行，短路
        if let Some(literal) = &self.require_literal {
            if !contains_ignore_ascii_case(input, literal) {
                return false;
            }
        }

        // 阶段3：结构前置any检查 - 有则执行，短路
        if let Some(any_list) = &self.require_any_literal {
            if !any_list.iter().any(|substr| input.contains(substr)) {
                return false;
            }
        }

        // 所有阶段通过/无阶段 → 放行
        true
    }

    /// 带阶段日志的check方法（供调试用）
    /// 返回：(是否通过, 失败阶段, 失败原因)
    #[inline(always)]
    pub fn check_with_log(
        &self,
        input: &str,
        input_tokens: &FxHashSet<String>,
        input_preview: &str,
        input_tokens_preview: &str,
        matcher_desc: &str,
    ) -> bool {
        // 阶段1：Token交集检查
        if let Some(tokens) = &self.require_tokens {
            let (pass_evidence, missing_evidence) =
                min_evidence_checker::check_min_evidence_prune_with_missing(tokens, input_tokens);
            
            if !pass_evidence {
                log::debug!(
                    "Stage1 (token) prune filtered | Input preview: {} | Evidence set: {:?} | Missing evidence: {:?} | Input tokens: {:?} | Rule: {}",
                    input_preview,
                    tokens,
                    missing_evidence,
                    input_tokens_preview,
                    matcher_desc
                );
                return false;
            } else {
                log::debug!(
                    "Stage1 (token) prune allowed | Reason: {} | Input preview: {} | Evidence set: {:?} | Rule: {}",
                    if tokens.is_empty() {
                        "Empty evidence set (fallback allow)"
                    } else {
                        "Token intersection matched"
                    },
                    input_preview,
                    tokens,
                    matcher_desc
                );
            }
        }

        // 阶段2：原始必现字面量检查
        if let Some(literal) = &self.require_literal {
            if !contains_ignore_ascii_case(input, literal) {
                log::debug!(
                    "Stage2 (literal) prune filtered | Input preview: {} | Required literal: {} | Rule: {}",
                    input_preview,
                    literal,
                    matcher_desc
                );
                return false;
            }
            log::debug!(
                "Stage2 (literal) prune allowed | Required literal: {} | Input preview: {} | Rule: {}",
                literal,
                input_preview,
                matcher_desc
            );
        }

        // 阶段3：结构前置Any检查（修复：改用contains_ignore_ascii_case）
        if let Some(any_list) = &self.require_any_literal {
            let hit = any_list.iter().any(|substr| contains_ignore_ascii_case(input, substr));
            if !hit {
                log::debug!(
                    "Stage3 (any literal) prune filtered | Input preview: {} | Required any: {:?} | Rule: {}",
                    input_preview,
                    any_list,
                    matcher_desc
                );
                return false;
            }
            log::debug!(
                "Stage3 (any literal) prune allowed | Required any: {:?} | Input preview: {} | Rule: {}",
                any_list,
                input_preview,
                matcher_desc
            );
        }

        // 所有阶段通过
        log::debug!(
            "All prune stages allowed | Input preview: {} | Rule: {}",
            input_preview,
            matcher_desc
        );
        true
    }

    /// 辅助方法：创建仅包含token检查的gate
    #[inline(always)]
    pub fn with_tokens(tokens: FxHashSet<String>) -> Self {
        Self {
            require_tokens: Some(tokens),
            require_literal: None,
            require_any_literal: None,
        }
    }

    /// 辅助方法：创建包含token+字面量的gate
    #[inline(always)]
    pub fn with_tokens_and_literal(tokens: FxHashSet<String>, literal: String) -> Self {
        Self {
            require_tokens: Some(tokens),
            require_literal: Some(literal),
            require_any_literal: None,
        }
    }

    /// 辅助方法：创建包含字面量+结构any的gate
    #[inline(always)]
    pub fn with_literal_and_any(literal: String, any_list: Vec<String>) -> Self {
        Self {
            require_tokens: None,
            require_literal: Some(literal),
            require_any_literal: if any_list.is_empty() {
                None
            } else {
                Some(any_list)
            },
        }
    }

    /// 辅助方法：仅包含结构any的gate
    #[inline(always)]
    pub fn with_any(any_list: Vec<String>) -> Self {
        Self {
            require_tokens: None,
            require_literal: None,
            require_any_literal: if any_list.is_empty() {
                None
            } else {
                Some(any_list)
            },
        }
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
