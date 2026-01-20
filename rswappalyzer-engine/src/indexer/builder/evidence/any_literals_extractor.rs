use once_cell::sync::Lazy;
use rustc_hash::FxHashSet;

// ========== 调试配置 ==========
/// 是否开启最小证据调试模式
const DEBUG_MIN_EVIDENCE: bool = false;
/// 调试关键字（仅匹配这些关键字的规则打印调试日志）
const DEBUG_KEYWORDS: &[&str] = &["?:apache", "jquery-ui"];

// ========== 核心配置常量 ==========
/// 结构化子串最小长度（过滤短无意义特征）
const MIN_STRUCTURAL_SUBSTR_LEN: usize = 3;
/// 长特征阈值（排序优先级：长特征 > 短特征）
const LONG_SUBSTR_THRESHOLD: usize = 5;

// 原子Token最小长度（业务特征最小粒度）
pub const MIN_ATOM_TOKEN_LEN: usize = 3;

// 全局弱字面量黑名单（过滤通用无业务特征的HTML关键字）
static WEAK_LITERAL_BLACKLIST: Lazy<FxHashSet<&'static str>> = Lazy::new(|| {
    let mut set = FxHashSet::default();
    set.extend([
        "html", "title", "link", "div", "a", "body", "span", "p", "ul", "li", "img",
        "script", "meta", "head", "stylesheet", "href", "class", "alt", "amp",
        "top", "pro", "assets", "downloads", "videos", "images", "cdn", "ico", "net", "com",
        "content", "core", "iframe", "param", "small", "sub", "code", "utils", "client",
        "medium", "large", ".ws", "header", ".min", ".js", "min.js", "ver", "msg", "public",
        "/img", "/images", "/css", "href=", " href=", "href=\"", "<link", "<div class=",
        "<div class=\"", "<html", "lang", "wtm",
    ]);
    set
});

/// 提取语义安全的任意字面量特征
/// 核心逻辑：仅解析OR分支，过滤通用黑名单，保留业务特征
pub fn extract_any_literals(pattern: &str) -> Vec<String> {
    let is_debug = DEBUG_MIN_EVIDENCE && DEBUG_KEYWORDS.iter().any(|kw| pattern.contains(kw));
    let mut log_buf = String::new();
    let mut safe_features = Vec::new();

    // 禁用全局必现特征（避免干扰OR分支提取）
    let global_static = String::new();
    if is_debug {
        log_buf.push_str(&format!("[全局必现特征] 提取结果: '{}'\n", global_static));
    }

    // 核心：解析OR分支提取字面量
    let or_literals = extract_or_branch_safe(pattern, is_debug, &mut log_buf);
    if !or_literals.is_empty() {
        safe_features.extend(or_literals);
    }

    // 去重+安全过滤（长度≥3、非黑名单、无正则元字符）
    let unique_safe = FxHashSet::from_iter(safe_features);
    let mut filtered = Vec::new();
    for s in unique_safe {
        // 清理首尾无效字符（. ) ( | ^ $）
        let cleaned = s
            .trim_end_matches(|c: char| c == '.' || c == ')' || c == '(' || c == '|' || c == '^')
            .trim_start_matches(|c: char| c == '^' || c == '$');
        
        // 安全过滤三规则
        let len_ok = cleaned.len() >= MIN_STRUCTURAL_SUBSTR_LEN;
        let not_black = !WEAK_LITERAL_BLACKLIST.contains(cleaned);
        let no_regex_meta = !cleaned.contains('?') && !cleaned.contains('{') && !cleaned.contains('}') && !cleaned.contains('[') && !cleaned.contains(']');
        
        if len_ok && not_black && no_regex_meta {
            filtered.push(cleaned.to_string());
        } else if is_debug {
            log_buf.push_str(&format!(
                "[DEBUG] 过滤特征 '{}' → 清理后: '{}', 长度达标: {}, 黑名单: {}, 含正则元字符: {}\n", 
                s, cleaned, len_ok, !not_black, !no_regex_meta
            ));
        }
    }

    // 特征排序（长特征优先 → 含特殊字符优先 → 长度降序）
    filtered.sort_by(|a, b| {
        let a_long = a.len() >= LONG_SUBSTR_THRESHOLD;
        let b_long = b.len() >= LONG_SUBSTR_THRESHOLD;
        if a_long != b_long {
            b_long.cmp(&a_long)
        } else {
            let a_feat = a.contains('-') || a.contains('_') || a.contains('.');
            let b_feat = b.contains('-') || b.contains('_') || b.contains('.');
            if a_feat != b_feat {
                b_feat.cmp(&a_feat)
            } else {
                b.len().cmp(&a.len())
            }
        }
    });

    // 调试日志打印
    if is_debug {
        println!("cargo:warning= [DEBUG] 规则: {}", pattern);
        println!("cargo:warning= [DEBUG] 最终特征: {:?}", filtered);
        if !log_buf.is_empty() {
            println!("cargo:warning= [DEBUG] 细节: {}", log_buf);
        }
    }

    filtered
}

/// 安全提取OR分支：仅解析括号外/非字符组内的顶级OR分支
fn extract_or_branch_safe(pattern: &str, is_debug: bool, log: &mut String) -> Vec<String> {
    let mut features = FxHashSet::default();
    let mut branches = Vec::new();
    let mut current_branch = String::new();
    let mut bracket_depth = 0;
    let mut in_escape = false;
    let mut in_char_class = false;

    // 逐字符解析OR分支（仅顶级|分割）
    for c in pattern.chars() {
        if in_escape {
            current_branch.push(c);
            in_escape = false;
            continue;
        }

        match c {
            '\\' => {
                in_escape = true;
                current_branch.push(c);
            }
            '[' => {
                in_char_class = true;
                current_branch.push(c);
            }
            ']' => {
                in_char_class = false;
                current_branch.push(c);
            }
            '(' => {
                bracket_depth += 1;
                current_branch.push(c);
            }
            ')' => {
                if bracket_depth > 0 {
                    bracket_depth -= 1;
                }
                current_branch.push(c);
            }
            '|' if bracket_depth == 0 && !in_char_class => {
                if !current_branch.trim().is_empty() {
                    branches.push(current_branch.trim().to_string());
                }
                current_branch.clear();
            }
            _ => current_branch.push(c),
        }
    }

    // 处理最后一个分支
    if !current_branch.trim().is_empty() {
        branches.push(current_branch.trim().to_string());
    }

    if is_debug {
        log.push_str(&format!("[OR分支] 解析结果: {:?}\n", branches));
    }

    // 提取每个分支的业务字面量
    for branch in branches {
        // 清理分支首尾的分组符 ((?: ... ))
        let clean_branch = branch
            .strip_prefix("(?:")
            .unwrap_or(&branch)
            .strip_prefix('(')
            .unwrap_or(&branch)
            .strip_suffix(')')
            .unwrap_or(&branch);

        let branch_features = extract_business_literals_safe(clean_branch);
        for feat in branch_features {
            if feat.len() >= MIN_ATOM_TOKEN_LEN {
                features.insert(feat);
            }
        }
    }

    features.into_iter().collect()
}

/// 安全提取业务字面量：正确处理转义符（如\s），避免错误拼接
fn extract_business_literals_safe(s: &str) -> Vec<String> {
    let mut literals = Vec::new();
    let mut current = String::new();
    let mut in_escape = false;
    let mut in_char_class = false; // 字符组 [ ] 内标记
    let mut in_quantifier = false; // 量词 { } 内标记

    for c in s.chars() {
        if in_escape {
            // 处理转义符后字符
            in_escape = false;
            match c {
                // 空白类转义符（\s/\t/\n等）：分割字面量，不拼接
                's' | 't' | 'n' | 'r' | 'f' | 'v' => {
                    save_valid_literal_safe(&mut literals, &mut current);
                    continue;
                }
                // 正则语法转义符（\d/\w等）：分割字面量
                'd' | 'w' | 'D' | 'W' | 'S' | 'T' => {
                    save_valid_literal_safe(&mut literals, &mut current);
                    continue;
                }
                // 普通转义字符（如\. \-）：保留为业务字符
                _ => current.push(c),
            }
            continue;
        }

        match c {
            '\\' => {
                in_escape = true;
                continue;
            }
            // 跳过字符组内内容
            '[' => {
                in_char_class = true;
                save_valid_literal_safe(&mut literals, &mut current);
                continue;
            }
            ']' => {
                in_char_class = false;
                continue;
            }
            // 跳过量词内内容
            '{' => {
                in_quantifier = true;
                save_valid_literal_safe(&mut literals, &mut current);
                continue;
            }
            '}' => {
                in_quantifier = false;
                continue;
            }
            // 分组符：分割字面量（分组内内容单独处理）
            '(' | ')' => {
                save_valid_literal_safe(&mut literals, &mut current);
                continue;
            }
            // 量词：分割字面量
            '?' | '*' | '+' | '$' | '^' if !in_char_class && !in_quantifier => {
                save_valid_literal_safe(&mut literals, &mut current);
                continue;
            }
            // 收集业务字符（字母/数字/-/_/.）
            c if !in_char_class && !in_quantifier => {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                    current.push(c);
                } else {
                    save_valid_literal_safe(&mut literals, &mut current);
                }
            }
            _ => continue,
        }
    }

    // 处理最后一段字面量
    save_valid_literal_safe(&mut literals, &mut current);

    literals
}

/// 辅助函数：保存有效字面量（清理首尾无效字符）
fn save_valid_literal_safe(literals: &mut Vec<String>, current: &mut String) {
    if !current.is_empty() {
        // 清理首尾的连字符/点
        let trimmed = current.trim_matches(|c: char| c == '-' || c == '.');
        if !trimmed.is_empty() {
            literals.push(trimmed.to_string());
        }
        current.clear();
    }
}

// ========== 单元测试 ==========
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_astro_pattern_extract() {
        // 测试正则：^astro\\sv([\\d\\.]+)$
        let pattern = r"^astro\sv([\d\.]+)$";
        let literals = extract_any_literals(pattern);
        // 验证：提取出astro/v，而非错误的astrosv
        assert!(literals.contains(&"astro".to_string()));
        assert!(literals.contains(&"v".to_string()));
        assert!(!literals.contains(&"astrosv".to_string()));
    }
}