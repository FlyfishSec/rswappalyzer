//! 正向剪枝策略分析器
//! 负责分析正则表达式的结构，输出安全的剪枝策略，并执行前置剪枝校验
use serde::{Deserialize, Serialize};

use crate::{regex_filter::regex_preprocess::{is_meta_char, is_regex_literal, strip_all_inline_modifiers}, utils::safe_lower::safe_lowercase};


/// 剪枝策略枚举
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PruneStrategy {
    None,
    AnchorPrefix(String),
    AnchorSuffix(String),
    Exact(String),
    Literal(String),
}

/// 正则剪枝策略分析器
#[inline(always)]
pub fn extract_prune_strategy(pattern: &str) -> PruneStrategy {
    let stripped_pat = strip_all_inline_modifiers(pattern);
    let pat = stripped_pat.as_ref();
    let len = pat.len();
    if len == 0 {
        return PruneStrategy::None;
    }

    // 零堆分配判断首尾字符 ^/$ ，替代Vec<char>，核心性能优化
    let first_char = pat.chars().next().unwrap();
    let last_char = pat.chars().last().unwrap();

    // 策略1: Exact(xxx) → 正则是 ^xxx$ 精准匹配
    if first_char == '^' && last_char == '$' {
        let literal = &pat[1..len - 1];
        if is_regex_literal(literal) {
            let literal_lower = safe_lowercase(literal);
            return PruneStrategy::Exact(literal_lower);
        }
    }

    // 策略2: AnchorPrefix(xxx) → 正则以^开头，前缀是纯字面
    if first_char == '^' {
        let mut prefix_end = 1;
        let mut chars = pat.chars().skip(1);
        while let Some(c) = chars.next() {
            if is_meta_char(c) { break; }
            prefix_end += c.len_utf8();
        }
        let prefix = &pat[1..prefix_end];
        if !prefix.is_empty() {
            let prefix_lower = safe_lowercase(prefix);
            return PruneStrategy::AnchorPrefix(prefix_lower);
        }
    }

    // 策略3: AnchorSuffix(xxx) → 正则以$结尾，后缀是纯字面
    if last_char == '$' {
        let mut suffix_start = len - 2;
        let mut chars = pat[0..suffix_start+1].chars().rev();
        while let Some(c) = chars.next() {
            if is_meta_char(c) { break; }
            suffix_start -= c.len_utf8();
        }
        let suffix = &pat[suffix_start + 1..len - 1];
        if !suffix.is_empty() {
            let suffix_lower = safe_lowercase(suffix);
            return PruneStrategy::AnchorSuffix(suffix_lower);
        }
    }

    // 策略4: 无锚点 + 纯字面正则 → 返回Literal(字面量) 安全剪枝
    if is_regex_literal(pat) {
        let literal_lower = safe_lowercase(pat);
        return PruneStrategy::Literal(literal_lower);
    }

    // 策略5: None → 无任何安全剪枝条件，直接跑正则
    PruneStrategy::None
}

/// 正向证明剪枝策略入口
#[inline(always)]
pub fn check_safe_prune(input: &str, strategy: &PruneStrategy) -> bool {
    let input_lower = safe_lowercase(input);
    match strategy {
        PruneStrategy::None => true,
        PruneStrategy::Exact(literal) => input_lower == *literal,
        PruneStrategy::AnchorPrefix(literal) => input_lower.starts_with(&**literal),
        PruneStrategy::AnchorSuffix(literal) => input_lower.ends_with(&**literal),
        PruneStrategy::Literal(literal) => input_lower.contains(&**literal),
    }
}