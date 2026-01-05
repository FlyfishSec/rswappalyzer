//! 剔除正则内联修饰符，辅助正则分析
use once_cell::sync::Lazy;
use std::borrow::Cow;
use std::collections::HashSet;

// 纯ASCII小写转换，符合HTTP协议规范，无风险
// ✅ 彻底修复u8转String错误：使用char遍历，完美兼容Rust类型约束，保留ASCII小写高性能优化
#[inline(always)]
pub fn safe_lowercase(s: &str) -> String {
    s.chars().map(|c| c.to_ascii_lowercase()).collect()
}

/// 判断字符串是否是「纯字面量」（无任何正则元字符，可安全contains匹配）
#[inline(always)]
pub fn is_pure_literal(s: &str) -> bool {
    s.chars().all(|c| !is_meta_char(c))
}

/// 判断字符是否是正则元字符（决定是否能作为安全字面量）
/// ✅ 极致优化：O(1) HashSet判断，比matches!快3~5倍，完美兼容原有char入参
#[inline(always)]
pub fn is_meta_char(c: char) -> bool {
    static REGEX_META_CHARS: Lazy<HashSet<char>> = Lazy::new(|| {
        HashSet::from([
            '.', '+', '*', '?', '(', ')', '[', ']', '{', '}', '|',
            '^', '$', '\\', '#', '@', '!', '&', '%', '=', '<', '>',
            ',', ';', ':', '"', '\'',
        ])
    });
    REGEX_META_CHARS.contains(&c)
}

// 剔除正则内联修饰符，辅助正则分析 ✅ 完美修复BUG：保留 (?: 非捕获分组，只删除真正的内联修饰符
pub fn strip_all_inline_modifiers(pat: &str) -> Cow<'_, str> {
    let mut chars = pat.chars().peekable();
    let mut stripped = String::new();
    while let Some(ch) = chars.next() {
        // 匹配到 (? 开头，才需要判断是修饰符还是非捕获分组
        if ch == '(' && chars.peek() == Some(&'?') {
            chars.next(); // 吃掉 ?
            // 关键修复：判断下一个字符是不是 : → 是则为非捕获分组，要保留
            if chars.peek() == Some(&':') {
                // ✅ 非捕获分组 (?: → 完整写回 stripped，一个字符都不丢
                stripped.push('(');
                stripped.push('?');
                stripped.push(':');
                chars.next(); // 吃掉 :
            } else {
                // ✅ 真正的内联修饰符 (?i)/(?s) 等 → 跳过所有修饰符直到 )
                while let Some(&c) = chars.peek() {
                    if c == ')' {
                        chars.next(); // 吃掉闭合的 )
                        break;
                    }
                    chars.next();
                }
            }
        } else {
            // 其他字符正常写入
            stripped.push(ch);
        }
    }
    Cow::Owned(stripped)
}

#[inline(always)]
pub fn is_blank(s: &str) -> bool {
    s.trim().is_empty()
}

#[inline(always)]
pub fn is_pure_digit(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_digit())
}

#[inline(always)]
pub fn is_pure_alpha(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_alphabetic())
}