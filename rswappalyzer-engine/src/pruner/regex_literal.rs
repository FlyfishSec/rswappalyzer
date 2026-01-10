use once_cell::sync::Lazy;
use regex::Regex;
use rustc_hash::FxHashSet;

use crate::tokenizer::MIN_ATOM_TOKEN_LEN;

// 最小长度阈值
const MIN_STRUCTURAL_SUBSTR_LEN: usize = 3;

// 仅过滤正则元字符
const REGEX_META: &[u8] = &[b'^', b'$', b'.', b'*', b'+', b'?', b'(', b')', b'[', b']', b'\\', b'{', b'}', b'|'];

// 预编译正则：匹配所有分组（捕获组/非捕获组）+ 无分组OR分支
static BRANCH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:\(\??:?)?([^()|]+)(?:\|[^()|]+)+\)?").unwrap()
});

pub fn extract_or_branch_literals(pattern: &str) -> Vec<String> {
    let mut set = FxHashSet::default();

    // 处理分组OR分支 (?:A|B|C) / (A|B|C)
    for cap in BRANCH_RE.captures_iter(pattern) {
        let Some(branch_body) = cap.get(1) else { continue; };
        let branch_body = branch_body.as_str();
        
        for item in branch_body.split('|') {
            let item = item.trim();
            if item.len() < MIN_ATOM_TOKEN_LEN { continue; }

            let has_meta = item.as_bytes().iter().any(|&b| REGEX_META.contains(&b));
            if !has_meta {
                set.insert(item.to_string());
            } else {
                let static_substr = extract_longest_static_substr(item);
                if !static_substr.is_empty() {
                    set.insert(static_substr);
                }
            }
        }
    }

    // 处理无分组OR分支 a|b|c
    if pattern.contains('|') && !pattern.contains('(') {
        for item in pattern.split('|') {
            let item = item.trim();
            if item.len() < MIN_ATOM_TOKEN_LEN { continue; }
            
            let has_meta = item.as_bytes().iter().any(|&b| REGEX_META.contains(&b));
            if !has_meta {
                set.insert(item.to_string());
            } else {
                let static_substr = extract_longest_static_substr(item);
                if !static_substr.is_empty() {
                    set.insert(static_substr);
                }
            }
        }
    }

    // 过滤：只保留长度 ≥3 的子串
    let mut literals: Vec<_> = set.into_iter()
        .filter(|s| s.len() >= MIN_STRUCTURAL_SUBSTR_LEN)
        .collect();

    // 排序：长串在前（匹配时优先检查长串，提升性能）
    literals.sort_by(|a, b| b.len().cmp(&a.len()));

    // 限制数量：最多保留3个（避免过多子串影响性能）
    if literals.len() > 3 {
        literals.truncate(3);
    }

    literals
}

// 从单分支正则提取最长静态子串
pub fn extract_longest_static_substr_from_regex(pattern: &str) -> String {
    let mut substr_candidates = Vec::new();
    let mut current_substr = String::new();
    let mut max_substr = String::new();

    // 跳过正则开头的锚点/量词
    let pattern = pattern.trim_start_matches('^').trim_end_matches('$');
    
    for &b in pattern.as_bytes() {
        if REGEX_META.contains(&b) {
            // 遇到元字符，检查当前静态子串
            if current_substr.len() > max_substr.len() && current_substr.len() >= MIN_ATOM_TOKEN_LEN {
                //max_substr = current_substr.clone();
                substr_candidates.push(current_substr.clone());
            }
            current_substr.clear();
        } else {
            // 转义字符处理（如 \. 转为 .）
            if b == b'\\' {
                continue;
            }
            current_substr.push(b as char);
        }
    }

    // 处理最后一段静态子串
    if current_substr.len() > max_substr.len() && current_substr.len() >= MIN_ATOM_TOKEN_LEN {
        substr_candidates.push(current_substr);
        //max_substr = current_substr;
    }

    //max_substr
    substr_candidates.into_iter().max_by_key(|s| s.len()).unwrap_or_default()

}

// 从含正则元字符的分支中提取最长静态子串
fn extract_longest_static_substr(s: &str) -> String {
    let mut max_substr = String::new();
    let mut current_substr = String::new();

    for &b in s.as_bytes() {
        if REGEX_META.contains(&b) {
            if current_substr.len() > max_substr.len() && current_substr.len() >= MIN_ATOM_TOKEN_LEN {
                // 用swap代替clone（零拷贝）
                std::mem::swap(&mut max_substr, &mut current_substr);
                // swap后current_substr持有原max_substr（空），直接clear即可
                current_substr.clear();
            } else {
                current_substr.clear();
            }
        } else {
            current_substr.push(b as char);
        }
    }

    // 处理最后一段子串
    if current_substr.len() > max_substr.len() && current_substr.len() >= MIN_ATOM_TOKEN_LEN {
        std::mem::swap(&mut max_substr, &mut current_substr);
    }

    max_substr
}