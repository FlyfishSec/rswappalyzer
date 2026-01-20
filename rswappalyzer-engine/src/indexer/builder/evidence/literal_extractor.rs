use crate::{
    regex_filter::regex_preprocess::strip_all_inline_modifiers, safe_lower::safe_lowercase,
};
use regex_syntax::{
    hir::{Hir, HirKind, Literal},
    Parser,
};
use rustc_hash::FxHashSet;

/// 调试旁路开关 - 编译期生效
const DEBUG_MIN_EVIDENCE: bool = false;

// ========== 核心配置常量：字面量有效性规则 ==========
/// 最小非纯特殊字符数量
const MIN_VALID_CHAR_COUNT: usize = 2;

/// 非纯特殊字符的判定规则：ASCII字母/数字（可扩展）
/// 修复：调整为接收 &char 引用，适配 filter 方法的参数要求
const VALID_CHAR_PREDICATE: fn(&char) -> bool = |c| c.is_ascii_alphanumeric();

/// 提取正则表达式中的**所有**最小必现字符串
/// 核心功能：分析正则HIR结构，找到所有分支/拼接中必然出现的字面量字符串集合
/// 修复点：1. 过滤纯特殊字符、基于常量限制最小有效字符数 2. 修复filter函数签名不匹配
pub fn extract_min_evidence_literal(pattern: &str) -> FxHashSet<String> {
    let is_debug_pattern = DEBUG_MIN_EVIDENCE
        && (pattern.contains(r"mathjax") || pattern.contains(r"mathjax"));

    if is_debug_pattern {
        println!(
            "cargo:warning= [DEBUG] Extracting min evidence literal for pattern: {}",
            pattern
        );
    }

    let pat_lower = safe_lowercase(pattern);
    let stripped = strip_all_inline_modifiers(&pat_lower);
    let pat = stripped.as_ref();

    let mut source_literals = if is_pure_literal(pat) {
        // 纯字面量正则：整个字符串是必现的，返回单元素集合
        let cleaned = clean_regex_anchors(pat);
        let mut set = FxHashSet::default();
        if !cleaned.is_empty() {
            set.insert(cleaned);
        }
        set
    } else {
        let hir = match Parser::new().parse(pat) {
            Ok(hir) => hir,
            Err(e) => {
                if is_debug_pattern {
                    println!(
                        "cargo:warning= [DEBUG] HIR parse failed, return empty set: {:?}",
                        e
                    );
                }
                return FxHashSet::default();
            }
        };
        // 提取HIR中的所有必现字面量（交集），直接返回集合（不再取最短）
        extract_hir_literals(&hir, is_debug_pattern)
    };

    // ========== 基于常量过滤无效字面量 ==========
    source_literals.retain(|lit| is_valid_literal(lit));

    if is_debug_pattern {
        println!(
            "cargo:warning= [DEBUG] Final result | Must literals: {:?}",
            source_literals
        );
    }

    source_literals
}

// 核心重构：递归处理HIR，提取所有字面量（逻辑不变）
fn extract_hir_literals(
    hir: &Hir,
    is_debug_pattern: bool,
) -> FxHashSet<String> {
    let mut literals = FxHashSet::default();

    match hir.kind() {
        HirKind::Literal(lit) => {
            let s = literal_to_string(lit);
            if let Some(s) = s {
                let s_cleaned = clean_regex_anchors(&s);
                if !s_cleaned.is_empty() {
                    if is_debug_pattern {
                        println!(
                            "cargo:warning= [DEBUG ROOT] literal={}",
                            s_cleaned
                        );
                    }
                    literals.insert(s_cleaned);
                }
            }
        }
        HirKind::Concat(subs) => {
            for h in subs {
                let sub_literals = extract_hir_literals(h, is_debug_pattern);
                literals.extend(sub_literals);
            }
        }
        HirKind::Alternation(subs) => {
            let mut branch_literal_sets = Vec::new();
            for branch in subs {
                let branch_literals = extract_hir_literals(branch, is_debug_pattern);
                branch_literal_sets.push(branch_literals);
            }

            if branch_literal_sets.is_empty() {
                return literals;
            }

            literals = branch_literal_sets[0].clone();
            for set in &branch_literal_sets[1..] {
                literals.retain(|t| set.contains(t));
                if literals.is_empty() {
                    break;
                }
            }
        }
        HirKind::Capture(cap) => {
            let cap_literals = extract_hir_literals(&cap.sub, is_debug_pattern);
            literals = cap_literals;
        }
        HirKind::Repetition(rep) => {
            if rep.min >= 1 {
                let rep_literals = extract_hir_literals(&rep.sub, is_debug_pattern);
                literals = rep_literals;
            }
        }
        _ => {}
    }

    literals
}

/// 判断是否为安全证据纯字面量正则（无正则语法符号）
fn is_pure_literal(s: &str) -> bool {
    s.chars().all(|c| {
        !matches!(
            c,
            '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\'
        )
    })
}

/// 字面量转字符串，空内容返回None
fn literal_to_string(lit: &Literal) -> Option<String> {
    let bytes: &[u8] = &lit.0;
    (!bytes.is_empty()).then_some(String::from_utf8_lossy(bytes).into_owned())
}

// 通用锚点清洗函数
fn clean_regex_anchors(s: &str) -> String {
    s.trim()
        .trim_start_matches('^')
        .trim_end_matches('$')
        .to_string()
}

// ========== 基于常量的有效字面量判断 ==========
/// 判断字面量是否有效：基于常量配置的规则
fn is_valid_literal(lit: &str) -> bool {
    // 基于常量 VALID_CHAR_PREDICATE 统计有效字符数
    let valid_char_count = lit.chars()
        .filter(VALID_CHAR_PREDICATE)  // 修复：移除多余的 &，直接传函数名
        .count();
    
    // 基于常量 MIN_VALID_CHAR_COUNT 判断是否达标
    valid_char_count >= MIN_VALID_CHAR_COUNT
}