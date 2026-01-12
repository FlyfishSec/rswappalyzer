use once_cell::sync::Lazy;
use regex::Regex;
use rustc_hash::FxHashSet;

use crate::tokenizer::MIN_ATOM_TOKEN_LEN;

// ========== 核心配置 ==========
// 最小长度阈值：保留短特征串（如 uk-）
const MIN_STRUCTURAL_SUBSTR_LEN: usize = 3;
// 超长特征串阈值：优先保留长特征（如 uk-container）
const LONG_SUBSTR_THRESHOLD: usize = 5;

// 仅保留真正的正则语法元字符（新增:）
const REGEX_SYNTAX_META: &[u8] = &[
    b'^', b'$', b'*', b'+', b'?', b'(', b')', b'[', b']', b'{', b'}', b'|', b':',
];

// 全局弱字面量黑名单
static WEAK_LITERAL_BLACKLIST: Lazy<FxHashSet<&'static str>> = Lazy::new(|| {
    let mut set = FxHashSet::default();
    set.extend([
        // HTML通用标签/属性
        "html",
        "title",
        "link",
        "div",
        "link",
        "a",
        "html",
        "body",
        "span",
        "p",
        "ul",
        "li",
        "img",
        "script",
        "meta",
        "head",
        "stylesheet",
        "href",
        "class",
        "alt",
        "amp",
        // 通用弱字面量
        "top",
        "pro",
        "assets",
        "downloads",
        "videos",
        "images",
        "cdn",
        "ico",
        "net",
        "com",
        "content",
        "core",
        "iframe",
        "param",
        "small",
        "sub",
        "core",
        "code",
        "utils",
        "client",
        "medium",
        "large",
        ".ws",
        "header",
        ".min",
        ".js",
        "min.js",
        "ver",
        "msg",
        "public",
        "/img",
        "/images",
        "/css",
        "href=",
        " href=",
        "href=\"",
        "<link",
        "<div class=",
        "<div class=\"",
        "<html",
        "lang",
        "wtm",
    ]);
    set
});

// 优化预编译正则：匹配OR分支（捕获组/非捕获组）
static BRANCH_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\((?:\?:)?([^()|]+(?:\|[^()|]+)+)\)").unwrap());

/// 提取“规则匹配的必要特征”（特征不存在 → 规则一定不匹配）
/// 用于最小证据后的兜底剪枝，仅返回“安全特征”
pub fn extract_semantic_safe_features(pattern: &str) -> Vec<String> {
    let mut safe_features = Vec::new();

    // 步骤1：提取正则中“全局必现的静态串”（语义安全）
    let global_static = extract_global_mandatory_static_str(pattern);
    if !global_static.is_empty() {
        safe_features.push(global_static);
    }

    // 步骤2：OR分支仅作为“补充安全特征”（全量保留）
    let or_literals = extract_or_branch_literals_safe(pattern);
    if !or_literals.is_empty() {
        safe_features.extend(or_literals);
    }

    // 去重+过滤通用词+最小长度
    let mut unique_safe = FxHashSet::from_iter(safe_features);
    unique_safe.retain(|s| {
        s.len() >= MIN_STRUCTURAL_SUBSTR_LEN && !WEAK_LITERAL_BLACKLIST.contains(s.as_str())
    });

    // 排序：优先超长串 → 含业务特征 → 长度（仅排序，不截断）
    let mut result: Vec<_> = unique_safe.into_iter().collect();
    result.sort_by(|a, b| {
        let a_is_long = a.len() >= LONG_SUBSTR_THRESHOLD;
        let b_is_long = b.len() >= LONG_SUBSTR_THRESHOLD;
        if a_is_long != b_is_long {
            b_is_long.cmp(&a_is_long)
        } else {
            let a_has_feature = a.contains('-') || a.contains('_') || a.contains('.');
            let b_has_feature = b.contains('-') || b.contains('_') || b.contains('.');
            if a_has_feature != b_has_feature {
                b_has_feature.cmp(&a_has_feature)
            } else {
                b.len().cmp(&a.len())
            }
        }
    });

    result
}

/// 提取正则中“全局必现的静态串”（语义安全：特征不存在 → 规则一定不匹配）
fn extract_global_mandatory_static_str(pattern: &str) -> String {
    let mut mandatory_parts = Vec::new();
    let mut current_part = String::new();
    let mut in_escape = false;
    let mut in_or_branch = false;
    let mut in_non_capture_group = false;
    let mut skip_next_colon = false;

    // 清理锚点
    let pattern_clean = pattern.trim_start_matches('^').trim_end_matches('$');
    let bytes = pattern_clean.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let &b = &bytes[i];
        match b {
            // 处理转义
            b'\\' if !in_escape => {
                in_escape = true;
                i += 1;
                continue;
            }
            // 识别非捕获组开头 (?
            b'(' if !in_escape && i + 1 < bytes.len() && bytes[i+1] == b'?' => {
                in_non_capture_group = true;
                skip_next_colon = true;
                i += 2;
                continue;
            }
            // 跳过非捕获组的:
            b':' if !in_escape && skip_next_colon => {
                skip_next_colon = false;
                i += 1;
                continue;
            }
            // 进入OR分支（标记，跳过OR内的内容）
            b'|' if !in_escape => {
                in_or_branch = true;
                if !current_part.is_empty() {
                    mandatory_parts.push(current_part.clone());
                    current_part.clear();
                }
                i += 1;
                continue;
            }
            // 退出OR分支/非捕获组（如括号闭合）
            b')' if !in_escape => {
                in_or_branch = false;
                in_non_capture_group = false;
                skip_next_colon = false;
                if !current_part.is_empty() {
                    mandatory_parts.push(current_part.clone());
                    current_part.clear();
                }
                i += 1;
                continue;
            }
            // 遇到正则元字符，截断必现部分（非OR分支内）
            c if !in_escape && !in_or_branch && !in_non_capture_group && REGEX_SYNTAX_META.contains(&c) => {
                if !current_part.is_empty() {
                    mandatory_parts.push(current_part.clone());
                    current_part.clear();
                }
                in_escape = false;
                i += 1;
            }
            // 收集必现字符（非OR分支、非元字符、非捕获组）
            _ if !in_or_branch && !in_non_capture_group => {
                current_part.push(b as char);
                in_escape = false;
                i += 1;
            }
            // 其他情况（OR分支/捕获组内）
            _ => {
                in_escape = false;
                i += 1;
            }
        }
    }

    // 处理最后一段必现部分
    if !current_part.is_empty() {
        mandatory_parts.push(current_part);
    }

    // 返回最长的全局必现静态串（语义安全）
    mandatory_parts
        .into_iter()
        .filter(|s| s.len() >= MIN_STRUCTURAL_SUBSTR_LEN)
        .max_by_key(|s| s.len())
        .unwrap_or_default()
}

/// 安全版OR分支提取：全量保留，仅作为补充特征
fn extract_or_branch_literals_safe(pattern: &str) -> Vec<String> {
    let mut set = FxHashSet::default();

    // 1. 处理分组OR分支 (?:A|B|C) / (A|B|C)
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

            let static_substr = extract_static_feature(item);
            if !static_substr.is_empty() {
                set.insert(static_substr);
            }
        }
    }

    // 2. 处理无分组OR分支 a|b|c
    if pattern.contains('|') && !pattern.contains('(') {
        for item in pattern.split('|') {
            let item = item.trim();
            if item.len() < MIN_ATOM_TOKEN_LEN {
                continue;
            }

            let static_substr = extract_static_feature(item);
            if !static_substr.is_empty() {
                set.insert(static_substr);
            }
        }
    }

    // 全量返回，不截断（仅过滤通用词和最小长度）
    set.into_iter()
        .filter(|s| s.len() >= MIN_STRUCTURAL_SUBSTR_LEN)
        .filter(|s| !WEAK_LITERAL_BLACKLIST.contains(s.as_str()))
        .collect()
}

/// 静态特征提取函数
fn extract_static_feature(s: &str) -> String {
    let mut static_str = String::new();
    let mut in_escape = false;

    for &b in s.as_bytes() {
        match b {
            b'\\' if !in_escape => {
                in_escape = true;
                continue;
            }
            c if !in_escape && REGEX_SYNTAX_META.contains(&c) => {
                continue;
            }
            _ => {
                static_str.push(b as char);
                in_escape = false;
            }
        }
    }

    static_str
}