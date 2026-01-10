use rswappalyzer_engine::tokenizer::{MAX_TOKEN_LIMIT, extract_atomic_tokens, is_valid_full_token_char};
use rustc_hash::FxHashSet;

#[inline(always)]
pub fn extract_input_tokens(input: &str) -> FxHashSet<String> {
    let mut tokens = FxHashSet::default();
    let mut current = String::with_capacity(16);

    // 按char遍历（保留完整字符串，包括中文）
    for c in input.chars() {
        if tokens.len() >= MAX_TOKEN_LIMIT { break; }
        
        let normalized_c = match c {
            // 大写转小写（仅ASCII）
            'A'..='Z' => c.to_ascii_lowercase(),
            // 有效完整Token字符：保留（和is_valid_full_token_char对齐）
            c if is_valid_full_token_char(c as u8) || c.is_cjk() => c,
            // 无效字符：截断当前Token
            _ => {
                if !current.is_empty() {
                    // 交给共用的extract_atomic_tokens处理
                    let atomic = extract_atomic_tokens(&current);
                    tokens.extend(atomic);
                    current.clear();
                }
                continue;
            }
        };
        current.push(normalized_c);
    }

    // 处理最后一段Token
    if !current.is_empty() && tokens.len() < MAX_TOKEN_LIMIT {
        let atomic = extract_atomic_tokens(&current);
        tokens.extend(atomic);
    }

    tokens
}

// 中文判断（仅用于保留完整字符串）
trait CharCjkExt {
    fn is_cjk(&self) -> bool;
}

impl CharCjkExt for char {
    #[inline(always)]
    fn is_cjk(&self) -> bool {
        // 先解引用self为char，再转为u32
        matches!(*self as u32,
            0x4E00..=0x9FFF | 0x3400..=0x4DBF | 0x20000..=0x2A6DF |
            0x2A700..=0x2B73F | 0x2B740..=0x2B81F | 0x2B820..=0x2CEAF |
            0x2CEB0..=0x2EBEF | 0xF900..=0xFAFF | 0x2F800..=0x2FA1F
        )
    }
}