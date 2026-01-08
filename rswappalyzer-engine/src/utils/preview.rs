use std::fmt::{self, Write};

// ======================== 输出截断工具函数 ========================
/// 空白字符折叠 + 截断 - 零堆分配的日志预览核心函数
/// 逻辑：
/// 1. 遍历字符，连续空白折叠为单个空格（不修改原字符串，仅格式化输出）
/// 2. 达到最大长度时立即终止，避免多余计算
/// 3. 全程无堆分配、无String创建
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
                // 达到最大长度，立即退出（避免多余遍历）
                if char_count >= self.max_length {
                    break;
                }

                if ch.is_whitespace() {
                    // 仅当最后一个字符不是空白时，才写入单个空格
                    if !last_was_whitespace {
                        f.write_str(" ")?;
                        char_count += 1;
                        last_was_whitespace = true;
                    }
                } else {
                    // 非空白字符直接写入
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
