//! 正则过滤 - 最小证据剪枝模块
//! 提供语义安全的最小证据提取、输入令牌提取、剪枝校验能力
use regex_syntax::Parser;
use regex_syntax::hir::{Hir, HirKind, Literal};
use rustc_hash::FxHashSet;

use crate::utils::regex_filter::common;


/// 最小证据剪枝入口
#[inline(always)]
pub fn min_evidence_prune_check(
    evidence_set: &FxHashSet<String>,
    input_tokens: &FxHashSet<String>
) -> bool {
    if evidence_set.is_empty() {
        return true;
    }
    // 直接用透传的token校验，零提取、零计算开销
    evidence_set.iter().all(|e| input_tokens.contains(e.as_str()))
}

/// 最小证据剪枝入口
#[inline(always)]
pub fn min_evidence_prune_check_with_missing(
    evidence_set: &FxHashSet<String>,
    input_tokens: &FxHashSet<String>
) -> (bool, Vec<String>) {
    if evidence_set.is_empty() {
        return (true, Vec::new());
    }
    let missing_evidence: Vec<_> = evidence_set.iter()
        .filter(|e| !input_tokens.contains(e.as_str()))
        .cloned()
        .collect();
    (missing_evidence.is_empty(), missing_evidence)
}

/// 基于 regex-syntax HIR 的必现字面量提取+原子化拆分
#[allow(dead_code)]
#[inline(always)]
pub fn extract_min_evidence_tokens(pattern: &str) -> FxHashSet<String> {
    // 全局唯一一次小写转换
    // 所有后续逻辑均基于这个预小写的&str切片操作，无任何二次小写
    let pat_lower = safe_lowercase(pattern);
    let stripped = common::strip_all_inline_modifiers(&pat_lower);
    let pat = stripped.as_ref();

    let mut evidence = FxHashSet::default();

    // 纯字面量正则，精准返回 + 只过滤长度≤2的短词
    if is_pure_literal(pat) {
        if pat.len() > 2 {
            evidence.insert(pat.to_string());
        }
        return evidence;
    }

    // HIR解析提取：智能过滤独立符号，杜绝jquery-这类错误
    let hir = match Parser::new().parse(pat) {
        Ok(hir) => hir,
        Err(_) => return safe_fallback_extract(pat),
    };
    collect_must_literals(&hir, &mut evidence);

    // 原地过滤规则：空值剔除 + 长度>2
    evidence.retain(|s| !s.is_empty() && s.len() > 2);

    // 兜底提取，同样只过滤短词
    if evidence.is_empty() {
        let fallback = safe_fallback_extract(pat);
        evidence.extend(fallback);
    }

    if evidence.is_empty() {
        let core = pat
            .split(|c: char| !c.is_ascii_alphanumeric())
            .next()
            .unwrap_or("");
        if core.len() >= 3 {
            evidence.insert(core.to_string());
        }
    }

    // 单一可变集合原子化拆分
    let mut atomic_evidence = FxHashSet::default();
    for literal in &evidence {
        let tokens = split_to_atomic_tokens(literal);
        atomic_evidence.extend(tokens);
    }

    // 返回优先级：有原子化结果则返回原子token集，无则返回原生集
    if !atomic_evidence.is_empty() {
        atomic_evidence
    } else {
        evidence
    }
}

/// 基于 regex-syntax HIR 的必现字面量提取
#[allow(dead_code)]
#[inline(always)]
pub fn extract_min_evidence(pattern: &str) -> FxHashSet<String> {
    let mut evidence = FxHashSet::default();

    let stripped = common::strip_all_inline_modifiers(pattern);
    let pat = stripped.as_ref();

    // 纯字面量正则，直接返回
    if is_pure_literal(pat) {
        evidence.insert(safe_lowercase(pat));
        return evidence;
    }

    // 使用 regex-syntax 解析为 HIR
    let hir = match Parser::new().parse(pat) {
        Ok(hir) => hir,
        Err(_) => return evidence, // 解析失败 → 不剪枝
    };

    collect_must_literals(&hir, &mut evidence);

    // 统一转为小写，全局大小写无关匹配
    let mut lower_evidence = FxHashSet::default();
    for s in evidence {
        lower_evidence.insert(safe_lowercase(&s));
    }

    lower_evidence.retain(|s| !s.is_empty());
    lower_evidence
}

// 智能HIR递归提取
fn collect_must_literals(hir: &Hir, out: &mut FxHashSet<String>) {
    match hir.kind() {
        HirKind::Literal(lit) => {
            let s = literal_to_string(lit);
            if let Some(s) = s {
                let has_valid_char = s.chars().any(|c| c.is_ascii_alphanumeric() || c == '_');
                let is_pure_symbol = s.chars().all(|c| !c.is_ascii_alphanumeric() && c != '_');
                if has_valid_char && !is_pure_symbol {
                    out.insert(s);
                }
            }
        }
        HirKind::Concat(subs) => {
            for h in subs {
                collect_must_literals(h, out);
            }
        }
        HirKind::Alternation(_subs) => {}
        HirKind::Capture(cap) => {
            collect_must_literals(&cap.sub, out);
        }
        HirKind::Repetition(rep) => {
            collect_must_literals(&rep.sub, out);
        }
        // 必现
        // HirKind::Repetition(rep) => {
        //     if rep.min > 0 {
        //         collect_must_literals(&rep.sub, out);
        //     }
        // }
        _ => {}
    }
}

// Literal字面量转字符串
fn literal_to_string(lit: &Literal) -> Option<String> {
    let bytes: &[u8] = &lit.0;
    (!bytes.is_empty()).then_some(String::from_utf8_lossy(bytes).into_owned())
}

/// 纯字面量判断
fn is_pure_literal(s: &str) -> bool {
    s.chars().all(|c| {
        !matches!(
            c,
            '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '^' | '$' | '\\'
        )
    })
}

#[inline(always)]
fn safe_lowercase(s: &str) -> String {
    s.chars().map(|c| c.to_ascii_lowercase()).collect()
}

// 智能兜底提取，兼容连字符两种场景
fn safe_fallback_extract(pattern: &str) -> FxHashSet<String> {
    let mut evidence = FxHashSet::default();
    let mut current = String::with_capacity(16);
    let pat_bytes = pattern.as_bytes();
    let len = pat_bytes.len();

    for (i, &c) in pat_bytes.iter().enumerate() {
        if c.is_ascii_alphanumeric() || c == b'_' {
            current.push(c as char);
        } else if c == b'-' && i > 0 && i < len - 1 {
            // ✅ 零成本随机访问 i-1/i+1，无需collect，无内存开销
            let prev_char = pat_bytes[i - 1];
            let next_char = pat_bytes[i + 1];
            if prev_char.is_ascii_alphabetic() && next_char.is_ascii_alphabetic() {
                current.push('-');
            } else {
                push_valid_token(&mut current, &mut evidence);
            }
        } else {
            push_valid_token(&mut current, &mut evidence);
        }
    }
    push_valid_token(&mut current, &mut evidence);
    evidence
}

// 辅助函数：只过滤短词，原地清空current，无堆内存分配/拷贝
#[inline(always)]
fn push_valid_token(current: &mut String, evidence: &mut FxHashSet<String>) {
    if current.len() > 2 {
        // 替代高版本的 current.take()，零拷贝/零分配，所有权转移，无 clone 开销，兼容全版本
        evidence.insert(std::mem::take(current));
    }
    current.clear();
}




const MAX_EVIDENCE_LITERAL_LEN: usize = 256;


/// 原子化分词核心工具
/// 输入：任意完整的最小证据字面量
/// 输出：拆分后的原子Token集合（过滤无效短token，长度>2）
#[inline(always)]
pub fn split_to_atomic_tokens(literal: &str) -> FxHashSet<String> {
    let mut atomic_tokens = FxHashSet::default();

    if literal.len() > MAX_EVIDENCE_LITERAL_LEN {
        return atomic_tokens; // 直接放弃，等价于“无高质量证据”
    }

    let bytes = literal.as_bytes();
    let mut start = 0;
    let len = bytes.len();

    // 手写纯ASCII单词扫描：\w+ 等价于 [a-zA-Z0-9_]，原地扫描无分配
    while start < len {
        // 跳过非单词字符
        while start < len && !bytes[start].is_ascii_alphanumeric() && bytes[start] != b'_' {
            start += 1;
        }
        let word_start = start;
        // 收集连续的单词字符
        while start < len && (bytes[start].is_ascii_alphanumeric() || bytes[start] == b'_') {
            start += 1;
        }
        // 提取单词切片，无拷贝
        let token = &literal[word_start..start];
        // 统一规则：和全局保持一致，只保留长度>2的有效token
        if token.len() > 2 {
            atomic_tokens.insert(token.to_string());
        }
    }

    atomic_tokens
}
