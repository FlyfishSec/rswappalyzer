use rustc_hash::FxHashSet;

// token提取数量上限常量
pub const MAX_TOKEN_LIMIT: usize = 10000;
// 原子token最小长度限制，过滤无意义短token
pub const MIN_ATOM_TOKEN_LEN: usize = 3;

/// 从任意输入文本提取「输入令牌集」
/// 双令牌机制：完整令牌 + 原子令牌，带数量上限+短token过滤，极致性能
#[inline(always)]
pub fn extract_input_tokens(input: &str) -> FxHashSet<String> {
    let mut tokens = FxHashSet::default();
    let mut current = String::with_capacity(16);
    let mut atom_buf = String::with_capacity(16); // 复用缓冲区，零额外分配

    for b in input.bytes() {
        // 数量超限直接终止，避免无意义计算
        if tokens.len() >= MAX_TOKEN_LIMIT {
            break;
        }
        let b = match b {
            b'A'..=b'Z' => b + 32, // 大写转小写，统一匹配规则
            b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' => b,
            _ => {
                if !current.is_empty() {
                    insert_full_and_atoms(&mut tokens, &mut current, &mut atom_buf);
                }
                continue;
            }
        };
        current.push(b as char);
    }

    if !current.is_empty() && tokens.len() < MAX_TOKEN_LIMIT {
        insert_full_and_atoms(&mut tokens, &mut current, &mut atom_buf);
    }

    tokens
}

#[inline(always)]
fn insert_full_and_atoms(
    tokens: &mut FxHashSet<String>,
    token: &mut String,
    atom_buf: &mut String,
) {
    let full_token = std::mem::take(token);
    // 插入完整token（完整token不限制长度，保证精准匹配）
    tokens.insert(full_token.clone());

    // 生成原子token + 过滤长度<3的无意义token
    atom_buf.clear();
    for b in full_token.bytes() {
        if b.is_ascii_alphanumeric() {
            atom_buf.push(b as char);
        } else if !atom_buf.is_empty() {
            // 核心优化：只插入长度>=3的原子token
            if atom_buf.len() >= MIN_ATOM_TOKEN_LEN {
                tokens.insert(std::mem::take(atom_buf));
            } else {
                atom_buf.clear();
            }
        }
    }
    // 处理最后一段原子token
    if !atom_buf.is_empty() && atom_buf.len() >= MIN_ATOM_TOKEN_LEN {
        tokens.insert(std::mem::take(atom_buf));
    }
}