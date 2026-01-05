//! 正则过滤 - 最小证据剪枝模块
//! 核心铁律(优先级最高)
//! 1. 仅提取正则匹配时100%必现内容，非必现内容一概舍弃，宁空勿脏
//! 2. HIR阶段不限长度，仅执行必现提取+脏数据过滤
//! 3. 最终TOKEN约束：长度>1，仅包含[a-zA-Z0-9_]
//! 4. 超长输入(>512字符)直接舍弃，TOKEN天然受输入长度约束无冗余判断
//! 5. HIR解析失败(保守兜底)：绝不提取非必现内容
//! 最终TOKEN为纯原子必现TOKEN，仅含[a-zA-Z0-9_]
use once_cell::sync::Lazy;
use regex::Regex;
use regex_syntax::hir::{Hir, HirKind, Literal};
use regex_syntax::Parser;
use rustc_hash::FxHashSet;


/// 全局常量 - TOKEN最小有效长度阈值 (最终过滤规则: 长度 > 此值)
pub const MIN_TOKEN_VALID_LENGTH: usize = 1;

/// 全局常量 - 原始输入字面量的最大阈值 (输入规则: 长度 ≤ 此值)
pub const MAX_INPUT_LITERAL_LENGTH: usize = 512;

/// 调试旁路开关 - 编译期生效，零性能侵入
/// 调试时改为true，发布时改为false即可，LLVM会自动剔除所有调试分支代码
const DEBUG_MIN_EVIDENCE: bool = false;

/// 基于regex-syntax HIR的必现字面量提取+强制原子化拆分
/// 核心返回规则：HIR解析失败 → 返回空集合，无兜底，杜绝脏数据
#[allow(dead_code)]
#[inline(always)]
pub fn extract_min_evidence_tokens(pattern: &str) -> FxHashSet<String> {
    let is_debug_pattern = DEBUG_MIN_EVIDENCE 
        && (pattern.contains(r"gambio") || pattern.contains(r"dreamweaver"));

    if is_debug_pattern {
        println!("cargo:warning= [DEBUG] Extracting min evidence tokens for pattern: {}", pattern);
    }

    let pat_lower = safe_lowercase(pattern);
    let stripped = crate::utils::regex_filter::common::strip_all_inline_modifiers(&pat_lower);
    let pat = stripped.as_ref();

    let mut raw_must_literals = FxHashSet::default();

    if is_pure_literal(pat) {
        let atomic_tokens = split_to_atomic_tokens(pat);
        raw_must_literals.extend(atomic_tokens);
    } else {
        let hir = match Parser::new().parse(pat) {
            Ok(hir) => {
                if is_debug_pattern {
                    println!("cargo:warning= [DEBUG] HIR parsed successfully: {:?}", hir);
                }
                hir
            }
            Err(e) => {
                if is_debug_pattern {
                    println!("cargo:warning= [DEBUG] HIR parse failed, return empty set: {:?}", e);
                }
                return FxHashSet::default();
            }
        };
        collect_must_literals(&hir, &mut raw_must_literals, is_debug_pattern);
    }

    // 最终统一过滤：所有过滤规则集中执行，单次生效
    let atomic_evidence: FxHashSet<String> = raw_must_literals
        .iter()
        .filter(|s| {
            s.chars().all(|c| c.is_ascii_alphanumeric())
                && s.len() > MIN_TOKEN_VALID_LENGTH
                && !s.is_empty()
        })
        .cloned()
        .collect();

    if is_debug_pattern {
        println!("cargo:warning= [DEBUG] Final atomic evidence tokens: {:?}", &atomic_evidence);
    }
    atomic_evidence
}

/// 基于regex-syntax HIR的必现字面量提取+强制原子化拆分（带兜底）
#[allow(dead_code)]
#[inline(always)]
pub fn extract_min_evidence_tokens_fallback(pattern: &str) -> FxHashSet<String> {
    let pat_lower = safe_lowercase(pattern);
    let stripped = crate::utils::regex_filter::common::strip_all_inline_modifiers(&pat_lower);
    let pat = stripped.as_ref();

    let mut raw_must_literals = FxHashSet::default();

    if is_pure_literal(pat) {
        let atomic_tokens = split_to_atomic_tokens(pat);
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

    let mut atomic_evidence = FxHashSet::default();
    for literal in &raw_must_literals {
        let atomic_tokens = split_to_atomic_tokens(literal);
        atomic_evidence.extend(atomic_tokens);
    }

    atomic_evidence
}

// ========== 仅修改此函数，其余所有代码完全无变更 ==========
fn collect_must_literals(hir: &Hir, out: &mut FxHashSet<String>, is_debug_pattern: bool) {
    match hir.kind() {
        HirKind::Literal(lit) => {
            let s = literal_to_string(lit);
            if let Some(s) = s {
                let s_trimmed = s.trim().trim_start_matches('^').trim_end_matches('$');
                if s_trimmed.is_empty() {
                    return;
                }
                let has_valid_char = s_trimmed.chars().any(|c| c.is_ascii_alphanumeric() || c == '_');
                let is_pure_symbol = s_trimmed.chars().all(|c| !c.is_ascii_alphanumeric() && c != '_');
                if has_valid_char && !is_pure_symbol {
                    let atomic_tokens = split_to_atomic_tokens(s_trimmed);
                    if is_debug_pattern {
                        println!("cargo:warning= [DEBUG ROOT] literal={}, split atomic tokens={:?}", s_trimmed, atomic_tokens);
                    }
                    out.extend(atomic_tokens);
                }
            }
        }
        HirKind::Concat(subs) => {
            // Concat为拼接整体，创建独立临时集合存储当前节点token，保证分支边界
            let mut concat_tokens = FxHashSet::default();
            for h in subs {
                collect_must_literals(h, &mut concat_tokens, is_debug_pattern);
            }
            out.extend(concat_tokens);
        }
        HirKind::Alternation(subs) => {
            if subs.is_empty() {
                return;
            }
            let mut branch_sets = Vec::new();
            // 每个分支创建独立token集合，彻底解决分支边界丢失问题
            for branch in subs {
                let mut branch_tokens = FxHashSet::default();
                collect_must_literals(branch, &mut branch_tokens, is_debug_pattern);
                branch_sets.push(branch_tokens);
            }
            // 严格交集计算：所有分支共有的token才是100%必现内容，遵循核心规则
            let mut common = branch_sets[0].clone();
            for set in &branch_sets[1..] {
                common.retain(|t| set.contains(t));
            }
            out.extend(common);
        }
        HirKind::Capture(cap) => {
            collect_must_literals(&cap.sub, out, is_debug_pattern);
        }
        HirKind::Repetition(rep) => {
            // 核心规则：可选/零次重复的内容不可能是必现内容，仅处理最小重复≥1的场景
            if rep.min >= 1 {
                collect_must_literals(&rep.sub, out, is_debug_pattern);
            }
        }
        _ => {}
    }
}

/// 字面量转字符串，空内容返回None
fn literal_to_string(lit: &Literal) -> Option<String> {
    let bytes: &[u8] = &lit.0;
    (!bytes.is_empty()).then_some(String::from_utf8_lossy(bytes).into_owned())
}

/// 判断是否为纯字面量正则（无正则语法符号）
fn is_pure_literal(s: &str) -> bool {
    s.chars().all(|c| {
        !matches!(
            c,
            '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\'
        )
    })
}

/// 安全转小写，仅转换ASCII字符，无异常panic
#[inline(always)]
pub fn safe_lowercase(s: &str) -> String {
    s.chars().map(|c| c.to_ascii_lowercase()).collect()
}

/// HIR解析失败后的安全兜底提取，保守过滤脏数据
#[inline(always)]
fn safe_fallback_extract(pattern: &str) -> FxHashSet<String> {
    let mut tokens = FxHashSet::default();
    let mut current_token = String::with_capacity(12);
    let mut has_optional_syntax = false;

    for c in pattern.chars() {
        if matches!(c, '|' | '(' | ')' | '[' | ']' | '+' | '*' | '?' | '\\') {
            has_optional_syntax = true;
            if !current_token.is_empty() && current_token.len() > MIN_TOKEN_VALID_LENGTH {
                tokens.insert(std::mem::take(&mut current_token));
            }
            break;
        }

        if !has_optional_syntax {
            if c.is_ascii_alphanumeric() || c == '_' {
                current_token.push(c);
            } else {
                if current_token.len() > MIN_TOKEN_VALID_LENGTH {
                    tokens.insert(std::mem::take(&mut current_token));
                } else {
                    current_token.clear();
                }
            }
        }
    }

    if !has_optional_syntax && current_token.len() > MIN_TOKEN_VALID_LENGTH {
        tokens.insert(current_token);
    }

    tokens
}

/// 拆分内容为原子TOKEN，仅拆分不过滤，超长内容直接返回空集合
#[inline(always)]
pub fn split_to_atomic_tokens(literal: &str) -> FxHashSet<String> {
    let mut atomic_tokens = FxHashSet::default();
    if literal.len() > MAX_INPUT_LITERAL_LENGTH {
        return atomic_tokens;
    }

    let mut current_token = String::with_capacity(16);
    for c in literal.chars() {
        if c.is_ascii_alphanumeric() {
            current_token.push(c);
        } else {
            if !current_token.is_empty() {
                atomic_tokens.insert(current_token.clone());
                current_token.clear();
            }
        }
    }

    if !current_token.is_empty() {
        atomic_tokens.insert(current_token);
    }
    atomic_tokens
}

/// 提取正则中 (?:A|B|C) 分支的所有字面量并集，适配结构前置剪枝
pub fn extract_or_branch_literals(pattern: &str) -> Vec<String> {
    let mut literals = Vec::new();
    let re = Lazy::new(|| Regex::new(r"\(\?:([^|)]+)(\|[^|)]+)*\)").unwrap());
    for cap in re.captures_iter(pattern) {
        let branch = cap.get(0).unwrap().as_str();
        let parts = branch.split('|').filter(|s| s.len() > 2);
        for part in parts {
            let lit = safe_lowercase(part);
            if !lit.is_empty() {
                literals.push(lit);
            }
        }
    }
    literals.dedup();
    literals
}