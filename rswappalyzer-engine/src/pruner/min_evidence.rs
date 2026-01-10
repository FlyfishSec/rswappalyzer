use crate::{
    regex_filter::regex_preprocess::strip_all_inline_modifiers, tokenizer::*,
    utils::safe_lower::safe_lowercase,
};
use regex_syntax::{
    hir::{Hir, HirKind, Literal},
    Parser,
};
use rustc_hash::{FxHashMap, FxHashSet};

/// 调试旁路开关 - 编译期生效，零性能侵入
const DEBUG_MIN_EVIDENCE: bool = true;

/// 最小证据元信息
#[derive(Debug, Clone)]
pub struct MinEvidenceMeta {
    /// 原子token集合（所有分支交集）
    pub tokens: FxHashSet<String>,
    /// 拆分前的原始必现字符串长度（仅交集token对应的共同字面量长度）
    pub source_len: usize,
    /// 原始必现子串
    pub source_literal: String,
}

// 新增：记录每个字面量的「原子token+长度」（核心：关联token和原始字面量）
#[derive(Debug, Clone)]
struct LiteralTokenInfo {
    /// 字面量字符串
    literal: String,
    /// 该字面量拆分的原子token
    tokens: FxHashSet<String>,
    /// 该字面量的原始长度
    len: usize,
}

#[inline(always)]
pub fn extract_min_evidence_meta(pattern: &str) -> MinEvidenceMeta {
    let is_debug_pattern =
        DEBUG_MIN_EVIDENCE && (pattern.contains(r"gophotoweb") || pattern.contains(r"vigbo"));

    if is_debug_pattern {
        println!(
            "cargo:warning= [DEBUG] Extracting min evidence tokens for pattern: {}",
            pattern
        );
    }

    let pat_lower = safe_lowercase(pattern);
    let stripped = strip_all_inline_modifiers(&pat_lower);
    let pat = stripped.as_ref();

    let mut raw_must_literals = FxHashSet::default();
    let mut source_len = 0;
    let mut source_literal = String::new();

    if is_pure_literal(pat) {
        // 纯字面量场景：直接关联字面量和token
        source_len = pat.len();
        source_literal = pat.to_string();
        raw_must_literals = extract_atomic_tokens(pat);
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
                return MinEvidenceMeta {
                    tokens: FxHashSet::default(),
                    source_len: 0,
                    source_literal: String::new(),
                };
            }
        };
        // 核心重构：递归提取token + 关联字面量长度
        let (tokens, literal_token_map) = extract_hir_tokens(&hir, is_debug_pattern);
        raw_must_literals = tokens;
        // 计算语义对齐的source_len + 必现子串
        let (len, literal) = calculate_source_len(&raw_must_literals, &literal_token_map);
        source_len = len;
        source_literal = literal;
    }

    raw_must_literals.retain(|s| !s.is_empty());

    if is_debug_pattern {
        println!(
            "cargo:warning= [DEBUG] Final result | Must tokens: {:?} | Must literal: '{}' | Source len: {}",
            &raw_must_literals, source_literal, source_len
        );
    }

    MinEvidenceMeta {
        tokens: raw_must_literals,
        source_len,
        source_literal,
    }
}

// 核心重构：递归处理HIR，提取token + 收集字面量信息
// 关键：Concat取并集，Alternation取交集
fn extract_hir_tokens(
    hir: &Hir,
    is_debug_pattern: bool,
) -> (FxHashSet<String>, FxHashMap<String, LiteralTokenInfo>) {
    let mut literal_token_map = FxHashMap::default();
    let mut tokens = FxHashSet::default();

    match hir.kind() {
        HirKind::Literal(lit) => {
            let s = literal_to_string(lit);
            if let Some(s) = s {
                let s_trimmed = s.trim().trim_start_matches('^').trim_end_matches('$');
                if s_trimmed.is_empty() {
                    return (tokens, literal_token_map);
                }
                let token_set = extract_atomic_tokens(s_trimmed);
                if is_debug_pattern {
                    println!(
                        "cargo:warning= [DEBUG ROOT] literal={}, split atomic tokens={:?}",
                        s_trimmed, token_set
                    );
                }
                // 记录字面量信息
                literal_token_map.insert(
                    s_trimmed.to_string(),
                    LiteralTokenInfo {
                        literal: s_trimmed.to_string(),
                        tokens: token_set.clone(),
                        len: s_trimmed.len(),
                    },
                );
                tokens = token_set;
            }
        }
        HirKind::Concat(subs) => {
            // 修复核心：拼接场景 → 所有子节点token的并集（而非交集）
            // 因为拼接的每个部分都需要出现，所以token是所有子节点的总和
            let mut concat_token_maps = Vec::new();
            for h in subs {
                let (sub_tokens, sub_map) = extract_hir_tokens(h, is_debug_pattern);
                // 并集：将子节点token加入当前集合
                tokens.extend(sub_tokens);
                concat_token_maps.push(sub_map);
            }
            // 合并字面量map
            for map in concat_token_maps {
                literal_token_map.extend(map);
            }
        }
        HirKind::Alternation(subs) => {
            // 分支场景：所有分支token的交集（仅共同出现的token）
            let mut branch_token_sets = Vec::new();
            let mut branch_token_maps = Vec::new();
            for branch in subs {
                let (branch_tokens, branch_map) = extract_hir_tokens(branch, is_debug_pattern);
                branch_token_sets.push(branch_tokens);
                branch_token_maps.push(branch_map);
            }

            if branch_token_sets.is_empty() {
                return (tokens, literal_token_map);
            }

            // 计算所有分支的token交集
            tokens = branch_token_sets[0].clone();
            for set in &branch_token_sets[1..] {
                tokens.retain(|t| set.contains(t));
                if tokens.is_empty() {
                    break;
                }
            }

            // 合并所有分支的字面量map
            for map in branch_token_maps {
                literal_token_map.extend(map);
            }
        }
        HirKind::Capture(cap) => {
            // 捕获组：递归处理子节点
            let (cap_tokens, cap_map) = extract_hir_tokens(&cap.sub, is_debug_pattern);
            tokens = cap_tokens;
            literal_token_map.extend(cap_map);
        }
        HirKind::Repetition(rep) => {
            // 重复场景：仅当最小重复数≥1时，提取子节点token
            if rep.min >= 1 {
                let (rep_tokens, rep_map) = extract_hir_tokens(&rep.sub, is_debug_pattern);
                tokens = rep_tokens;
                literal_token_map.extend(rep_map);
            }
        }
        // 其他HIR类型：无token
        _ => {}
    }

    (tokens, literal_token_map)
}

// 核心：计算source_len + 返回对应的必现子串
fn calculate_source_len(common_tokens: &FxHashSet<String>, literal_token_map: &FxHashMap<String, LiteralTokenInfo>) -> (usize, String) {
    if common_tokens.is_empty() {
        return (0, String::new()); // 无交集token → 长度0，无必现子串
    }

    // 找出所有包含「全部交集token」的字面量（共同必现字面量）
    let mut common_literals = Vec::new();
    for info in literal_token_map.values() {
        // 该字面量包含所有交集token → 是共同必现字面量
        let contains_all_common = common_tokens.iter()
            .all(|t| info.tokens.contains(t));
        if contains_all_common {
            common_literals.push((info.len, info.literal.clone()));
        }
    }

    if common_literals.is_empty() {
        return (0, String::new()); // 无符合条件的字面量 → 长度0
    }

    // 取最小长度的必现子串（保守原则）
    common_literals.sort_by_key(|&(len, _)| len);
    let (min_len, min_literal) = common_literals[0].clone();
    (min_len, min_literal)
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
pub fn extract_min_evidence_meta_fallback(pattern: &str) -> MinEvidenceMeta {
    let pat_lower = safe_lowercase(pattern);
    let stripped = strip_all_inline_modifiers(&pat_lower);
    let pat = stripped.as_ref();

    let mut raw_must_literals = FxHashSet::default();
    let mut source_len = 0;
    let mut source_literal = String::new();

    if is_pure_literal(pat) {
        source_len = pat.len();
        source_literal = pat.to_string();
        raw_must_literals = extract_atomic_tokens(pat);
    } else {
        let hir = match Parser::new().parse(pat) {
            Ok(hir) => hir,
            Err(_) => {
                let fallback = safe_fallback_extract(pat);
                return MinEvidenceMeta {
                    tokens: fallback,
                    source_len: 0,
                    source_literal: String::new(),
                };
            }
        };
        let (tokens, literal_map) = extract_hir_tokens(&hir, false);
        raw_must_literals = tokens;
        let (len, literal) = calculate_source_len(&raw_must_literals, &literal_map);
        source_len = len;
        source_literal = literal;
    }

    raw_must_literals.retain(|s| !s.is_empty());

    // 兜底逻辑：无token时提取安全字面量
    if raw_must_literals.is_empty() {
        let safe_fallback = safe_fallback_extract(pat);
        raw_must_literals.extend(safe_fallback);
        if !raw_must_literals.is_empty() {
            source_len = pat.len();
            source_literal = pat.to_string();
        }
    }

    MinEvidenceMeta {
        tokens: raw_must_literals,
        source_len,
        source_literal,
    }
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