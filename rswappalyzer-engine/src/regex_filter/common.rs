//! 剔除正则内联修饰符，辅助正则分析
use std::borrow::Cow;

/// 判断字符串是否是「纯字面量」（无任何正则元字符，可安全contains匹配）
#[inline]
pub fn is_pure_literal(s: &str) -> bool {
    s.chars().all(|c| !is_meta_char(c))
}

/// 判断字符是否是正则元字符（决定是否能作为安全字面量）
#[inline]
pub fn is_meta_char(c: char) -> bool {
    matches!(c, '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '^' | '$' | '\\' | '#' | '@' | '!' | '&' | '%' | '=' | '<' | '>' | ',' | ';' | ':' | '"' | '\'')
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