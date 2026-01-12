/// 安全转小写，仅转换ASCII字符
#[inline(always)]
pub fn safe_lowercase(s: &str) -> String {
    s.chars().map(|c| c.to_ascii_lowercase()).collect()
}

// 忽略大小写匹配方法(ASCII only)
#[inline(always)]
pub fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || n.len() > h.len() {
        return false;
    }

    h.windows(n.len()).any(|w| {
        w.iter()
            .zip(n.iter())
            .all(|(&a, &b)| a.to_ascii_lowercase() == b.to_ascii_lowercase())
    })
}

/// 支持Unicode的忽略大小写包含匹配
#[inline(always)]
#[allow(dead_code)]
pub fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let needle_chars: Vec<char> = needle.chars().collect();
    let needle_len = needle_chars.len();
    if needle_len > haystack.chars().count() {
        return false;
    }

    // 滑动窗口遍历字符
    haystack
        .chars()
        .collect::<Vec<char>>()
        .windows(needle_len)
        .any(|window| {
            window
                .iter()
                .zip(needle_chars.iter())
                .all(|(&h_char, &n_char)| h_char.to_lowercase().eq(n_char.to_lowercase()))
        })
}
