use rustc_hash::FxHashSet;
use std::fmt::{self, Write};

// ======================== 核心：零堆分配字符串格式化========================
/// 空白字符折叠 + 截断 - 零堆分配的日志预览核心函数
/// 核心优势：无堆分配、无String创建、遍历到最大长度立即终止
/// 适用所有字符串日志场景（替代所有其他字符串截断函数）
#[inline(always)]
pub fn preview_compact<'a>(s: &'a str, max_len: usize) -> impl fmt::Display + 'a {
    struct CompactView<'a> {
        source: &'a str,
        max_length: usize,
    }

    impl<'a> fmt::Display for CompactView<'a> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let mut char_count = 0;
            let mut last_was_whitespace = false;

            for ch in self.source.chars() {
                if char_count >= self.max_length {
                    // 超长时添加省略号（仅这一步有极小开销，可选）
                    if char_count == self.max_length {
                        f.write_str("…")?;
                    }
                    break;
                }

                if ch.is_whitespace() {
                    if !last_was_whitespace {
                        f.write_str(" ")?;
                        char_count += 1;
                        last_was_whitespace = true;
                    }
                } else {
                    f.write_char(ch)?;
                    char_count += 1;
                    last_was_whitespace = false;
                }
            }
            Ok(())
        }
    }

    CompactView {
        source: s,
        max_length: max_len,
    }
}

// ======================== 衍生：Token集合日志格式化 ========================
/// Token集合日志格式化（基于preview_compact，零堆分配核心）
/// 格式：[token1, token2, ...] (total: N)
#[inline(always)]
pub fn compress_token_set_default(tokens: &FxHashSet<String>) -> String {
    let total_count = tokens.len();
    if total_count == 0 {
        return "[empty]".to_string();
    }

    const MAX_COUNT: usize = 10; // 最多显示10个token
    const MAX_TOKEN_LEN: usize = 30; // 每个token最多30字符

    let mut result = String::with_capacity(MAX_COUNT * (MAX_TOKEN_LEN + 2) + 20); // 预分配容量
    result.push('[');

    // 遍历前N个token，用preview_compact格式化（零堆分配）
    for (idx, token) in tokens.iter().take(MAX_COUNT).enumerate() {
        if idx > 0 {
            result.push_str(", ");
        }
        // 复用核心函数，零堆分配写入
        write!(result, "{}", preview_compact(token, MAX_TOKEN_LEN)).unwrap();
    }

    // 补充总数信息
    if total_count > MAX_COUNT {
        write!(result, "… (total: {})", total_count).unwrap();
    }
    result.push(']');

    result
}