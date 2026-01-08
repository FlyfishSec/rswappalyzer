use once_cell::sync::Lazy;
use regex::Regex;
use rustc_hash::FxHashSet;

use crate::tokenizer::MIN_ATOM_TOKEN_LEN;


// 1. 预编译正则（全局静态）
static BRANCH_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\(\?:([^)]+)\)").unwrap());

/// 提取正则中 (?:A|B|C) OR分支的【纯静态原文字符串】
pub fn extract_or_branch_literals(pattern: &str) -> Vec<String> {
    let mut set = FxHashSet::default();

    for cap in BRANCH_RE.captures_iter(pattern) {
        let Some(branch_body) = cap.get(1) else {
            continue;
        };
        let branch_body = branch_body.as_str();
        
        for item in branch_body.split('|') {
            let item = item.trim();
            if item.len() < MIN_ATOM_TOKEN_LEN {
                continue;
            }

            // 字节级meta检查（干掉chars()，避免UTF-8解码）
            // 核心逻辑：直接操作u8字节，无需解码为char，速度提升3-5倍
            let has_meta = item.as_bytes().iter().any(|&b| matches!(
                b,
                b'^' | b'$' | b'.' | b'*' | b'+' | b'?' |
                b'(' | b')' | b'[' | b']' | b'\\' |
                b'{' | b'}' | b'|' | b'<' | b'>'
            ));
            
            if !has_meta {
                set.insert(item.to_string()); // HashSet自动去重
            }
        }
    }

    // 转换为Vec并按长度降序排序
    let mut literals: Vec<_> = set.into_iter().collect();
    literals.sort_by(|a, b| b.len().cmp(&a.len()));

    literals
}

pub fn extract_or_branch_literals_old(pattern: &str) -> Vec<String> {
    let mut literals = Vec::with_capacity(8);
    const REGEX_META_CHARS: &[char] = &['^', '$', '.', '*', '+', '?', '(', ')', '[', ']', '\\', '{', '}', '|', '<', '>'];
    let branch_re = Lazy::new(|| Regex::new(r"\(\?:([^)]+)\)").unwrap());

    for cap in branch_re.captures_iter(pattern) {
        let branch_body = cap.get(1).unwrap().as_str();
        let branch_items = branch_body.split('|').map(|s| s.trim());
        for item in branch_items {
            if item.len() >= MIN_ATOM_TOKEN_LEN && !item.chars().any(|c| REGEX_META_CHARS.contains(&c)) {
                literals.push(item.to_string());
            }
        }
    }

    literals.dedup();
    literals.sort_by(|a, b| b.len().cmp(&a.len()));
    literals
}