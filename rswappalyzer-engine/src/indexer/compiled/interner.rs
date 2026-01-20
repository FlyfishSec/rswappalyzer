use rustc_hash::FxHashMap;
use serde::{Serialize, Deserialize};

// ========== NewType 封装 ID（编译期防混用，零成本） ==========
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct TechId(pub u32);

#[repr(transparent)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct LiteralId(pub u32);

#[repr(transparent)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct TokenId(pub u32);

// ID 便捷方法
impl TechId {
    pub fn as_u32(&self) -> u32 { self.0 }
}

impl LiteralId {
    pub fn as_u32(&self) -> u32 { self.0 }
}

impl TokenId {
    pub fn as_u32(&self) -> u32 { self.0 }
}

// ========== Tech 名映射池 ==========
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechInterner {
    pub id_to_name: Vec<String>,
    pub name_to_id: FxHashMap<String, TechId>,
}

impl Default for TechInterner {
    fn default() -> Self {
        Self {
            id_to_name: Vec::new(),
            name_to_id: FxHashMap::default(),
        }
    }
}

impl TechInterner {
    /// 获取/插入 Tech 名，返回 ID（不存在则新增）
    pub fn get_or_insert(&mut self, name: &str) -> TechId {
        if let Some(&id) = self.name_to_id.get(name) {
            return id;
        }
        let id = TechId(self.id_to_name.len() as u32);
        self.id_to_name.push(name.to_string());
        self.name_to_id.insert(name.to_string(), id);
        id
    }

    /// 通过 ID 获取 Tech 名（O(1)）
    pub fn get_name(&self, id: TechId) -> Option<&str> {
        self.id_to_name.get(id.0 as usize).map(|s| s.as_str())
    }
}

// ========== Literal/Any/Contains 映射池 ==========
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiteralInterner {
    pub id_to_literal: Vec<String>,
    pub literal_to_id: FxHashMap<String, LiteralId>,
}

impl Default for LiteralInterner {
    fn default() -> Self {
        Self {
            id_to_literal: Vec::new(),
            literal_to_id: FxHashMap::default(),
        }
    }
}

impl LiteralInterner {
    /// 获取/插入特征串，返回 ID（不存在则新增）
    pub fn get_or_insert(&mut self, literal: &str) -> LiteralId {
        if let Some(&id) = self.literal_to_id.get(literal) {
            return id;
        }
        let id = LiteralId(self.id_to_literal.len() as u32);
        self.id_to_literal.push(literal.to_string());
        self.literal_to_id.insert(literal.to_string(), id);
        id
    }

    /// 通过 ID 获取特征串（O(1)）
    pub fn get_literal(&self, id: LiteralId) -> Option<&str> {
        self.id_to_literal.get(id.0 as usize).map(|s| s.as_str())
    }
    
    /// 仅查询 Literal 对应的 ID（不存在则返回 None，不插入）
    pub fn get_id(&self, literal: &str) -> Option<LiteralId> {
        self.literal_to_id.get(literal).copied()
    }
}

// ========== Token 映射池 ==========
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInterner {
    pub id_to_token: Vec<String>,
    pub token_to_id: FxHashMap<String, TokenId>,
}

impl Default for TokenInterner {
    fn default() -> Self {
        Self {
            id_to_token: Vec::new(),
            token_to_id: FxHashMap::default(),
        }
    }
}

impl TokenInterner {
    /// 获取/插入 Token，返回 ID（不存在则新增）
    pub fn get_or_insert(&mut self, token: &str) -> TokenId {
        if let Some(&id) = self.token_to_id.get(token) {
            return id;
        }
        let id = TokenId(self.id_to_token.len() as u32);
        self.id_to_token.push(token.to_string());
        self.token_to_id.insert(token.to_string(), id);
        id
    }

    /// 通过 ID 获取 Token（O(1)）
    #[inline(always)]
    pub fn get_token(&self, id: TokenId) -> Option<&str> {
        self.id_to_token.get(id.0 as usize).map(|s| s.as_str())
    }

    /// 仅查询 Token 对应的 ID（不存在则返回 None，不插入）
    #[inline(always)]
    pub fn get_id(&self, token: &str) -> Option<TokenId> {
        self.token_to_id.get(token).copied()
    }
}