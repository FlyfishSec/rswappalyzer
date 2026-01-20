use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Serialize, Deserialize};
use crate::{CompiledTechRule, TechBasicInfo, indexer::{compiled::{LiteralInterner, TechInterner, interner::{LiteralId, TechId}}, enums::Scope}};

// ========== 编译后规则库 ==========
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CompiledRuleLibrary {
    // 核心元数据（保留 String 键，保证可读性，仅一份存储）
    pub tech_patterns: FxHashMap<String, CompiledTechRule>,
    pub category_map: FxHashMap<u32, String>,
    pub tech_meta: FxHashMap<String, TechBasicInfo>,

    /// literal 反向索引：LiteralId → scope → TechId
    pub literal_index: FxHashMap<LiteralId, FxHashMap<Scope, FxHashSet<TechId>>>,
    /// 全局 literal：Vec<LiteralId>（用于 AC 构建）
    pub known_literals: Vec<LiteralId>,
    /// 按 scope 分组 literal：scope → LiteralId
    pub known_literals_by_scope: FxHashMap<Scope, FxHashSet<LiteralId>>,
    
    /// any 反向索引：LiteralId → scope → TechId
    pub any_index: FxHashMap<LiteralId, FxHashMap<Scope, FxHashSet<TechId>>>,
    /// 全局 any literal：Vec<LiteralId>
    pub known_any_literals: Vec<LiteralId>,
    /// 按 scope 分组 any literal：scope → LiteralId
    pub known_any_by_scope: FxHashMap<Scope, FxHashSet<LiteralId>>,
    
    /// contains 反向索引：LiteralId → scope → TechId
    pub contains_index: FxHashMap<LiteralId, FxHashMap<Scope, FxHashSet<TechId>>>,
    pub known_contains: Vec<LiteralId>,
    pub known_contains_by_scope: FxHashMap<Scope, FxHashSet<LiteralId>>,

    /// 无证据规则：scope → TechId
    pub no_evidence_index: FxHashMap<Scope, FxHashSet<TechId>>,
    
    // /// 最小证据规则：TokenId → scope → TechId
    // pub evidence_index: FxHashMap<TokenId, FxHashMap<Scope, FxHashSet<TechId>>>,
    // /// 全局唯一 token：TokenId（替代 String）
    // pub known_tokens: FxHashSet<TokenId>,
    // /// 按 scope 分组 token：scope → TokenId
    // pub known_tokens_by_scope: FxHashMap<Scope, FxHashSet<TokenId>>,
}

// ========== 序列化 Bundle（保证 ID 和映射池的一致性） ==========
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledBundle {
    /// 核心规则库（仅存储 ID）
    pub library: CompiledRuleLibrary,
    /// Tech 名 ↔ ID 映射池（必须和 library 一起序列化）
    pub tech_interner: TechInterner,
    /// Literal/Any/Contains ↔ ID 映射池
    pub literal_interner: LiteralInterner,
    // /// Token ↔ ID 映射池
    // pub token_interner: TokenInterner,
}

impl CompiledBundle {
    // 便捷方法：通过 TechId 获取 Tech 名
    pub fn get_tech_name(&self, tech_id: TechId) -> Option<&str> {
        self.tech_interner.get_name(tech_id)
    }

    // 便捷方法：通过 LiteralId 获取特征串
    pub fn get_literal(&self, lit_id: LiteralId) -> Option<&str> {
        self.literal_interner.get_literal(lit_id)
    }

    // 便捷方法：通过 TokenId 获取 Token 串
    // pub fn get_token(&self, token_id: TokenId) -> Option<&str> {
    //     self.token_interner.get_token(token_id)
    // }
}