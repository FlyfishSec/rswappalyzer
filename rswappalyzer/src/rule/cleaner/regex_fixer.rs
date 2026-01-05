//! 负责所有正则相关的修复逻辑
use once_cell::sync::Lazy;
use regex::Regex;

// 正则常量（懒加载，避免重复编译）
static LOOK_AROUND_REGEX: Lazy<Regex> = Lazy::new(|| {
    // 粗略匹配所有环视（包括内部嵌套非捕获分组），非精确解析
    // 支持：一层嵌套括号 + 不规则空白 + 所有4种环视类型
    Regex::new(r#"\(\?\s*(?:=|!|<=|<!)((?:[^()]|\([^()]*\))*)\)"#).unwrap()
});

static VERSION_MARKER_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(\\?;version:\\?\d+)"#).unwrap()
});

static SIMPLE_CONTAINS_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"^[^.*+?^$()\[\]\\|]+$"#).unwrap()
});

static SIMPLE_STARTS_WITH_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"^\^[^.*+?^$()\[\]\\|]+$"#).unwrap()
});

/// 正则修复器（专门处理正则模式的修复与类型判断）
#[derive(Debug, Default)]
pub struct RegexFixer;

impl RegexFixer {
    /// 判断是否为简单包含匹配（无正则特殊字符）
    pub fn is_simple_contains(&self, pattern: &str) -> bool {
        SIMPLE_CONTAINS_REGEX.is_match(pattern)
    }

    /// 判断是否为简单前缀匹配（^ + 无正则特殊字符）
    pub fn is_simple_starts_with(&self, pattern: &str) -> bool {
        SIMPLE_STARTS_WITH_REGEX.is_match(pattern)
    }

    /// 移除PCRE分隔符（首尾的/）
    pub fn remove_pcre_delimiter(&self, pattern: &str) -> String {
        if pattern.starts_with('/') && pattern.ends_with('/') && pattern.len() >= 2 {
            pattern[1..pattern.len()-1].to_string()
        } else {
            pattern.to_string()
        }
    }

    /// 移除版本标记（;version:\?\d+等）
    pub fn remove_version_marker(&self, pattern: &str) -> String {
        VERSION_MARKER_REGEX.replace_all(pattern, "").to_string()
    }

    /// 移除环视语法（(?=)(?!)(?<=)(?<!)等，不支持）
    pub fn remove_look_around(&self, pattern: &str) -> String {
        LOOK_AROUND_REGEX.replace_all(pattern, "").to_string()
    }

    /// 清理无效转义字符（仅保留合法的转义）
    pub fn clean_invalid_escapes(&self, pattern: &str) -> (String, bool) {
        let mut cleaned = String::new();
        let mut is_escaping = false;
        let mut fixed = false;

        for c in pattern.chars() {
            if is_escaping {
                // 合法的转义字符（正则支持的）
                match c {
                    // 包含：正则元字符 + 预定义字符类的字母（d/D/w/W/s/S）
                    '\\' | '.' | '*' | '+' | '?' | '^' | '$' | '(' | ')' |
                    '[' | ']' | '{' | '}' | '|' |
                    'd' | 'D' | 'w' | 'W' | 's' | 'S' => {
                        cleaned.push('\\');
                        cleaned.push(c); // 保留合法转义
                    }
                    _ => {
                        cleaned.push(c); // 视为无效转义，丢弃前面的\，直接保留原字符
                        fixed = true;
                    }
                }
                is_escaping = false;
            } else {
                if c == '\\' {
                    is_escaping = true;
                } else {
                    cleaned.push(c);
                }
            }
        }

        // 处理末尾残留的\
        if is_escaping {
            cleaned.push('\\');
            fixed = true;
        }

        (cleaned, fixed)
    }
    
    /// 安全修复正则字符集中的无效连字符
    /// 1. 合法场景不修改：[a-z]（范围）、[-abc]（开头连字符）、[abc-]（结尾连字符）
    /// 2. 修复场景：字符集中间的孤立连字符（无前后字符形成范围）、纯连字符集合
    /// 3. 处理未闭合的字符集
    pub fn fix_charset_hyphen_safe(&self, pattern: &str) -> (String, bool) {
        let mut cleaned = String::new();
        let mut in_charset = false;
        let mut charset_chars: Vec<char> = Vec::new();
        let mut fixed = false;
    
        for c in pattern.chars() {
            if !in_charset {
                // 不在字符集中，正常拼接，遇到 [ 则进入字符集处理
                if c == '[' {
                    in_charset = true;
                    charset_chars.clear(); // 清空之前的字符集缓存
                } else {
                    cleaned.push(c);
                }
            } else {
                // 在字符集中，遇到 ] 则处理字符集并退出
                if c == ']' {
                    in_charset = false;
                    let processed_charset = self.process_valid_charset(&charset_chars, &mut fixed);
                    cleaned.push('[');
                    cleaned.push_str(&processed_charset);
                    cleaned.push(']');
                    charset_chars.clear();
                } else {
                    // 未遇到 ]，继续收集字符集内的字符
                    charset_chars.push(c);
                }
            }
        }
    
        // 处理未闭合的字符集（没有匹配的 ]）
        if !charset_chars.is_empty() {
            let processed_charset = self.process_valid_charset(&charset_chars, &mut fixed);
            cleaned.push('[');
            cleaned.push_str(&processed_charset);
            fixed = true; // 未闭合本身属于需要标记的异常
        }
    
        (cleaned, fixed)
    }
    
    /// 内部辅助函数：处理单个字符集的内容，安全修复无效连字符
    fn process_valid_charset(&self, charset_chars: &[char], fixed: &mut bool) -> String {
        let len = charset_chars.len();
        if len == 0 {
            return String::new(); // 空字符集直接返回空
        }
    
        let mut processed = String::new();
        for (i, &c) in charset_chars.iter().enumerate() {
            if c == '-' {
                // 判断是否是需要转义的无效连字符
                let is_first = i == 0;
                let is_last = i == len - 1;
                let is_valid_range = if !is_first && !is_last {
                    // 中间连字符：判断前后是否是普通字符（能形成合法范围）
                    // 注：这里是基础判断，如需支持 \w、\d 等元字符，可扩展逻辑
                    let prev_char = charset_chars[i-1];
                    let next_char = charset_chars[i+1];
                    // 合法范围的简单判断：前后都是非特殊字符（可根据需求扩展）
                    prev_char.is_ascii_alphanumeric() && next_char.is_ascii_alphanumeric()
                } else {
                    false
                };
    
                if is_first || is_last || is_valid_range {
                    // 无需转义：首尾连字符 或 合法范围连字符
                    processed.push('-');
                } else {
                    // 无效连字符：需要转义，并标记修复
                    processed.push('\\');
                    processed.push('-');
                    *fixed = true;
                }
            } else {
                // 非连字符，直接拼接
                processed.push(c);
            }
        }
    
        processed
    }

    /// 修复未闭合的分组（补充缺失的)）
    pub fn fix_unbalanced_groups(&self, pattern: &str) -> (String, bool) {
        // 未闭合的分组计数（仅统计非转义的(）
        let mut open_group_count = 0;
        // 最终清理后的正则字符串
        let mut cleaned_pattern = String::new();
        // 标记是否处于转义状态（前一个字符是 \，当前字符是转义后的字面量）
        let mut is_escaping = false;
    
        // 遍历正则字符串的每个字符，逐字符处理
        for current_char in pattern.chars() {
            if is_escaping {
                // 1. 处于转义状态：当前字符是字面量，直接保留，不参与分组统计
                cleaned_pattern.push(current_char);
                // 转义状态仅持续一个字符，处理完后重置
                is_escaping = false;
                continue;
            }
    
            // 2. 非转义状态，分字符处理
            match current_char {
                '\\' => {
                    // 遇到转义符 \，标记为转义状态，同时保留 \
                    cleaned_pattern.push(current_char);
                    is_escaping = true;
                }
                '(' => {
                    // 遇到非转义的 (：分组开始，计数+1，同时保留 (
                    open_group_count += 1;
                    cleaned_pattern.push(current_char);
                }
                ')' => {
                    // 遇到非转义的 )：仅当有未闭合分组时，才减少计数，始终保留 )
                    if open_group_count > 0 {
                        open_group_count -= 1;
                    }
                    cleaned_pattern.push(current_char);
                }
                _ => {
                    // 其他普通字符（如字母、数字、.、+ 等），直接保留
                    cleaned_pattern.push(current_char);
                }
            }
        }
    
        // 3. 补充缺失的 )：仅针对非转义分组导致的未闭合
        let mut is_fixed = false;
        for _ in 0..open_group_count {
            cleaned_pattern.push(')');
            is_fixed = true; // 标记已修复（补充了括号）
        }
    
        (cleaned_pattern, is_fixed)
    }
    
    /// 修复无效字符集（空字符集、仅含特殊字符的字符集）
    pub fn fix_invalid_charset(&self, pattern: &str) -> (String, bool) {
        let mut cleaned = String::new();
        let mut in_charset = false;
        let mut charset_content = String::new();
        let mut fixed = false;

        for c in pattern.chars() {
            if !in_charset {
                if c == '[' {
                    in_charset = true;
                    charset_content.clear();
                } else {
                    cleaned.push(c);
                }
            } else {
                if c == ']' {
                    in_charset = false;
                    let charset_trimmed = charset_content.trim();
                    // 过滤空字符集或仅含特殊字符的字符集
                    if charset_trimmed.is_empty() || charset_trimmed == "^" || charset_trimmed == "-" {
                        fixed = true;
                    } else {
                        cleaned.push('[');
                        cleaned.push_str(charset_trimmed);
                        cleaned.push(']');
                    }
                } else {
                    charset_content.push(c);
                }
            }
        }

        // 处理未闭合的字符集
        if in_charset {
            let charset_trimmed = charset_content.trim();
            if !charset_trimmed.is_empty() && charset_trimmed != "^" && charset_trimmed != "-" {
                cleaned.push('[');
                cleaned.push_str(charset_trimmed);
            }
            fixed = true;
        }

        (cleaned, fixed)
    }
}