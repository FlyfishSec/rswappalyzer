use std::mem;

use rustc_hash::FxHashSet;
use rswappalyzer_engine::tokenizer::*;

#[inline(always)]
pub fn extract_input_tokens(input: &str) -> FxHashSet<String> {
    let mut tokens = FxHashSet::default();
    let mut current = String::with_capacity(16);

    for b in input.bytes() {
        if tokens.len() >= MAX_TOKEN_LIMIT { break; } // 数量超限终止
        let b = match b {
            b'A'..=b'Z' => b + 32, // 大写转小写，保留
            b if is_valid_full_token_char(b) => b, // 复用公共字符规则，保留
            _ => {
                if !current.is_empty() {
                    insert_only_atoms(&mut tokens, &mut current);
                }
                continue;
            }
        };
        current.push(b as char);
    }

    if !current.is_empty() && tokens.len() < MAX_TOKEN_LIMIT {
        insert_only_atoms(&mut tokens, &mut current);
    }

    tokens
}

#[inline(always)]
// 仅原子Token提取+插入
fn insert_only_atoms(
    tokens: &mut FxHashSet<String>,
    token: &mut String,
) {
    let full_token = mem::take(token);
    
    // 仅调用公共原子令牌提取函数，规则统一，无任何冗余
    let atomic_tokens = extract_atomic_tokens(&full_token);
    tokens.extend(atomic_tokens);
}