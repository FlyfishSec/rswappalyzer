use regex_syntax::{Parser, hir::{Hir, HirKind, Literal}};
use rustc_hash::FxHashSet;
use crate::{regex_filter::regex_preprocess::strip_all_inline_modifiers, tokenizer::*, utils::safe_lower::safe_lowercase};


/// 调试旁路开关 - 编译期生效，零性能侵入
const DEBUG_MIN_EVIDENCE: bool = false;

#[inline(always)]
pub fn extract_min_evidence_tokens(pattern: &str) -> FxHashSet<String> {
    let is_debug_pattern = DEBUG_MIN_EVIDENCE 
        && (pattern.contains(r"gambio") || pattern.contains(r"dreamweaver"));

    if is_debug_pattern {
        println!("cargo:warning= [DEBUG] Extracting min evidence tokens for pattern: {}", pattern);
    }

    let pat_lower = safe_lowercase(pattern);
    let stripped = strip_all_inline_modifiers(&pat_lower);
    let pat = stripped.as_ref();

    let mut raw_must_literals = FxHashSet::default();

    if is_pure_literal(pat) {
        let atomic_tokens = extract_atomic_tokens(pat);
        raw_must_literals.extend(atomic_tokens);
    } else {
        let hir = match Parser::new().parse(pat) {
            Ok(hir) => hir,
            Err(e) => {
                if is_debug_pattern {
                    println!("cargo:warning= [DEBUG] HIR parse failed, return empty set: {:?}", e);
                }
                return FxHashSet::default();
            }
        };
        collect_must_literals(&hir, &mut raw_must_literals, is_debug_pattern);
    }

    raw_must_literals.retain(|s| !s.is_empty());

    if is_debug_pattern {
        println!("cargo:warning= [DEBUG] Final atomic evidence tokens: {:?}", &raw_must_literals);
    }
    raw_must_literals
}

// 智能HIR递归提取
fn collect_must_literals(hir: &Hir, out: &mut FxHashSet<String>, is_debug_pattern: bool) {
    match hir.kind() {
        HirKind::Literal(lit) => {
            let s = literal_to_string(lit);
            if let Some(s) = s {
                let s_trimmed = s.trim().trim_start_matches('^').trim_end_matches('$');
                if s_trimmed.is_empty() { return; }
                let atomic_tokens = extract_atomic_tokens(s_trimmed);
                if is_debug_pattern {
                    println!("cargo:warning= [DEBUG ROOT] literal={}, split atomic tokens={:?}", s_trimmed, atomic_tokens);
                }
                out.extend(atomic_tokens);
            }
        }
        // 分支1: Concat 独立匹配
        HirKind::Concat(subs) => {
            let mut concat_tokens = FxHashSet::default();
            for h in subs { collect_must_literals(h, &mut concat_tokens, is_debug_pattern); }
            out.extend(concat_tokens);
        }
        // 分支2: Alternation 独立匹配
        HirKind::Alternation(subs) => {
            if subs.is_empty() { return; }
            let mut branch_sets = Vec::new();
            for branch in subs {
                let mut branch_tokens = FxHashSet::default();
                collect_must_literals(branch, &mut branch_tokens, is_debug_pattern);
                branch_sets.push(branch_tokens);
            }
            // 分支只有1个时，无需计算交集，直接复用
            if branch_sets.len() == 1 {
                out.extend(branch_sets[0].clone());
                return;
            }
            let mut common = branch_sets[0].clone();
            for set in &branch_sets[1..] { common.retain(|t| set.contains(t)); }
            out.extend(common);
        }
        // 分支3: Capture 独立匹配
        HirKind::Capture(cap) => {
            collect_must_literals(&cap.sub, out, is_debug_pattern);
        }
        // 分支4: Repetition 独立匹配
        HirKind::Repetition(rep) => {
            if rep.min >= 1 { collect_must_literals(&rep.sub, out, is_debug_pattern); }
        }
        // 兜底匹配所有其他HirKind，无逻辑
        _ => {}
    }
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


#[inline(always)]
pub fn extract_min_evidence_tokens_fallback(pattern: &str) -> FxHashSet<String> {
    let pat_lower = safe_lowercase(pattern);
    let stripped = strip_all_inline_modifiers(&pat_lower);
    let pat = stripped.as_ref();

    let mut raw_must_literals = FxHashSet::default();

    if is_pure_literal(pat) {
        let atomic_tokens = extract_atomic_tokens(pat);
        raw_must_literals.extend(atomic_tokens);
    } else {
        let hir = match Parser::new().parse(pat) {
            Ok(hir) => hir,
            Err(_) => return safe_fallback_extract(pat),
        };
        collect_must_literals(&hir, &mut raw_must_literals, false);
    }

    raw_must_literals.retain(|s| !s.is_empty());

    if raw_must_literals.is_empty() {
        let safe_fallback = safe_fallback_extract(pat);
        raw_must_literals.extend(safe_fallback);
    }

    raw_must_literals
}


/// HIR解析失败后的安全兜底提取，保守过滤脏数据
#[inline(always)]
fn safe_fallback_extract(pattern: &str) -> FxHashSet<String> {
    let mut tokens = FxHashSet::default();
    let mut has_optional_syntax = false;

    for c in pattern.chars() {
        if matches!(c, '|' | '(' | ')' | '[' | ']' | '+' | '*' | '?' | '\\') {
            has_optional_syntax = true;
            break;
        }
    }

    if !has_optional_syntax {
        tokens = extract_atomic_tokens(pattern);
    }

    tokens
}


