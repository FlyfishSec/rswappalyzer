use rustc_hash::FxHashSet;
use std::mem;

// 全局统一常量
/// token提取数量上限常量 - 全局统一
pub const MAX_TOKEN_LIMIT: usize = 10000;
/// 原子token最小长度限制 - 全局统一，过滤无意义短token，必须≥3
pub const MIN_ATOM_TOKEN_LEN: usize = 3;
/// 原始输入字面量的最大阈值 - 正则证据侧专用
pub const MAX_INPUT_LITERAL_LENGTH: usize = 512;
/// 有效原子字符集：仅包含这些字符的内容才会被作为原子token - 全局统一
#[inline(always)]
pub fn is_valid_atomic_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}
/// 有效完整token字符集：输入侧完整token的合法字符 - 全局统一
#[inline(always)]
pub fn is_valid_full_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-'
}

/// 公共核心：将任意字符串拆分为【合规原子令牌集】
/// 规则：仅保留[a-z0-9_]、长度≥3、去重、超长直接返回空、零冗余分配
#[inline(always)]
pub fn extract_atomic_tokens(s: &str) -> FxHashSet<String> {
    let mut tokens = FxHashSet::default();
    if s.len() > MAX_INPUT_LITERAL_LENGTH {
        return tokens;
    }
    let mut buf = String::with_capacity(16);
    for c in s.chars() {
        let b = c as u8;
        if is_valid_atomic_char(b) {
            buf.push(c.to_ascii_lowercase()); // 统一转小写，全局唯一规则
        } else if !buf.is_empty() {
            if buf.len() >= MIN_ATOM_TOKEN_LEN {
                tokens.insert(mem::take(&mut buf));
            } else {
                buf.clear();
            }
        }
    }
    // 处理最后一段原子token
    if !buf.is_empty() && buf.len() >= MIN_ATOM_TOKEN_LEN {
        tokens.insert(buf);
    }
    tokens
}
