//! 字符串格式化工具模块
//! 核心能力：零堆分配的字符串压缩/截断，高性能日志预览格式化

use rustc_hash::FxHashSet;
use std::borrow::Borrow;
use std::fmt::{self, Write};

// ======================== 核心：零堆分配字符串格式化 ========================
/// 空白字符折叠 + 长度截断（零堆分配）
/// 
/// 对字符串进行轻量化格式化：折叠连续空白字符为单个空格，超出最大长度时添加省略号，
/// 全程无堆分配、无String创建，遍历到最大长度立即终止，最大化性能。
/// 
/// # 生命周期
/// - `'a`: 绑定输入字符串的引用生命周期
/// 
/// # 参数
/// - `s`: 待格式化的源字符串
/// - `max_len`: 最大展示长度（含省略号）
/// 
/// # 返回值
/// 实现 Display trait 的格式化视图（延迟格式化，仅在输出时执行逻辑）
#[inline(always)]
pub fn preview_compact<'a>(s: &'a str, max_len: usize) -> impl fmt::Display + 'a {
    /// 延迟格式化视图结构体（内部使用）
    struct CompactView<'a> {
        source: &'a str,
        max_length: usize,
    }

    impl<'a> fmt::Display for CompactView<'a> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let mut char_count = 0;
            let mut last_was_whitespace = false;

            for ch in self.source.chars() {
                // 达到最大长度时添加省略号并终止遍历
                if char_count >= self.max_length {
                    if char_count == self.max_length {
                        f.write_str("…")?;
                    }
                    break;
                }

                // 折叠连续空白字符为单个空格
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

// ======================== 泛型Token集合格式化 ========================
/// 泛型Token集合格式化（零拷贝支持）
/// 
/// 对Token集合进行轻量化格式化展示：
/// 1. 最多显示指定数量的Token
/// 2. 单个Token使用 preview_compact 截断
/// 3. 补充总数信息（超出数量时）
/// 支持 String/&String/&str 等所有可转为 &str 的类型，零拷贝处理。
/// 
/// # 泛型参数
/// - `T`: 可转为 &str 的类型（Borrow<str> 约束）
/// 
/// # 参数
/// - `tokens`: Token集合（FxHashSet）
/// 
/// # 返回值
/// 格式化后的字符串（预分配容量，最小化堆分配）
#[inline(always)]
pub fn compress_token_set_generic<T: Borrow<str>>(tokens: &FxHashSet<T>) -> String {
    let total_count = tokens.len();
    if total_count == 0 {
        return "[empty]".to_string();
    }

    /// 最大展示Token数量
    const MAX_COUNT: usize = 10;
    /// 单个Token最大展示长度
    const MAX_TOKEN_LEN: usize = 30;

    // 预分配容量，减少堆分配次数
    let mut result = String::with_capacity(MAX_COUNT * (MAX_TOKEN_LEN + 2) + 20);
    result.push('[');

    // 遍历前N个Token并格式化
    for (idx, token) in tokens.iter().take(MAX_COUNT).enumerate() {
        if idx > 0 {
            result.push_str(", ");
        }
        // 零拷贝转为&str并压缩格式化
        write!(result, "{}", preview_compact(token.borrow(), MAX_TOKEN_LEN)).unwrap();
    }

    // 补充总数信息（超出最大展示数量时）
    if total_count > MAX_COUNT {
        write!(result, "… (total: {})", total_count).unwrap();
    }
    result.push(']');

    result
}

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