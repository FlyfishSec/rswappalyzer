use std::sync::Arc;

use rustc_hash::FxHashSet;
use serde::{Deserialize, Serialize};

use crate::{prune_strategy::PruneStrategy, Matcher};

// 纯静态的匹配规则描述体
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MatcherSpec {
    Contains(String),
    StartsWith(String),
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
            MatcherSpec::StartsWith(s) => Matcher::StartsWith(Arc::new(s.clone())),
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

/// 匹配准入网关 - 编译期折叠后的统一剪枝规则
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub enum MatchGate {
    /// 无任何准入条件，直接执行匹配（对应原 None/Exists）
    #[default]
    Open,
    /// 锚点级快速剪枝（优先级最高，对应原 PruneStrategy::AnchorPrefix/AnchorSuffix/Exact）
    Anchor(PruneStrategy),
    /// 最小证据剪枝（交集，铁律，对应原 min_evidence_set，零误杀核心）
    RequireAll(FxHashSet<String>),
    /// 结构前置剪枝（并集，准入门槛，对应原 StructuralPrereq，适配 (A|B|C) 正则）
    RequireAnyLiteral(Vec<String>),
}

impl MatchGate {
    /// 运行期剪枝校验核心方法 - 内联优化，零开销，短路执行
    #[inline(always)]
    pub fn check(&self, input: &str, input_tokens: &FxHashSet<String>) -> bool {
        match self {
            MatchGate::Open => true,
            MatchGate::Anchor(strategy) => match strategy {
                PruneStrategy::None => true,
                PruneStrategy::AnchorPrefix(p) => input.starts_with(p),
                PruneStrategy::AnchorSuffix(s) => input.ends_with(s),
                PruneStrategy::Exact(e) => input == e,
                PruneStrategy::Literal(l) => input.contains(l),
            },
            MatchGate::RequireAll(set) => set.iter().all(|t| input_tokens.contains(t.as_str())),
            MatchGate::RequireAnyLiteral(list) => {
                // Structural literals (non-atomic, non-tokenizable).
                // Checked via raw substring search by design.
                // Count is intentionally small (<=3).
                list.iter().any(|substr| input.contains(substr))
            }
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
