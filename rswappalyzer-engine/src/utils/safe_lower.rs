

/// 安全转小写，仅转换ASCII字符
#[inline(always)]
pub fn safe_lowercase(s: &str) -> String {
    s.chars().map(|c| c.to_ascii_lowercase()).collect()
}
