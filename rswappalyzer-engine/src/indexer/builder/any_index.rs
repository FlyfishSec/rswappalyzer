//! Any 索引构建器
//! 负责构建 any literal 反向索引

use crate::{
    builder::index_utils::{
        finalize_known_literals, get_vec_literals, process_patterns, CONTENT_SCOPES, KEYED_SCOPES,
    },
    compiled::{LiteralId, LiteralInterner, PatternEvidence, TechId, TechInterner},
    CompiledTechRule, Scope,
};
use rustc_hash::{FxHashMap, FxHashSet};

// 核心：定义Any literal长度限制常量（支持空值/短字面量兼容）
/// 内容型规则的最小any literal长度
const ANY_LITERAL_MIN_LENGTH_CONTENT: usize = 3;
/// KV型规则的最小any literal长度
const ANY_LITERAL_MIN_LENGTH_KEYED: usize = 3;
/// 全局known_any_literals的最小长度
const ANY_LITERAL_MIN_LENGTH_GLOBAL: usize = 3;

/// Any 索引构建结果（基于 ID 而非字符串）
#[derive(Debug, Clone)]
pub struct AnyIndexBuildResult {
    /// any_literal -> scope -> techs 反向索引
    pub any_index: FxHashMap<LiteralId, FxHashMap<Scope, FxHashSet<TechId>>>,
    /// 全局已知 any literal 列表（便于构建 AC）
    pub known_any_literals: Vec<LiteralId>,
    /// 按 scope 分组的 known_any_literals
    pub known_any_by_scope: FxHashMap<Scope, FxHashSet<LiteralId>>,
}

/// Any 索引构建器
pub struct AnyIndexBuilder;

impl AnyIndexBuilder {
    /// 构建 Any literal 相关索引
    pub fn build(
        compiled_tech: &FxHashMap<String, CompiledTechRule>,
        literal_interner: &mut LiteralInterner,
        tech_interner: &mut TechInterner,
    ) -> AnyIndexBuildResult {
        let mut any_index = FxHashMap::default();
        let mut known_any_literals = FxHashSet::default();
        let mut known_any_by_scope = FxHashMap::default();

        // 遍历所有技术规则，提取 any literal 证据
        for (tech_name, tech_rule) in compiled_tech {
            // 将 tech 名称转换为 TechId
            let tech_id = tech_interner.get_or_insert(tech_name);

            // ========== 处理内容型规则（URL/HTML/Script） ==========
            for (_name, get_patterns, scope) in CONTENT_SCOPES {
                let patterns = get_patterns(tech_rule);
                process_patterns(
                    tech_id,
                    patterns,
                    *scope,
                    literal_interner,
                    ANY_LITERAL_MIN_LENGTH_CONTENT,
                    &mut any_index,
                    &mut known_any_literals,
                    &mut known_any_by_scope,
                    get_vec_literals(|evidence: &PatternEvidence| &evidence.any_literals),
                );
            }

            // ========== 处理KV型规则（Meta/Header/Cookie） ==========
            for (_name, get_patterns, scope) in KEYED_SCOPES {
                let patterns = get_patterns(tech_rule);
                process_patterns(
                    tech_id,
                    patterns,
                    *scope,
                    literal_interner,
                    ANY_LITERAL_MIN_LENGTH_KEYED,
                    &mut any_index,
                    &mut known_any_literals,
                    &mut known_any_by_scope,
                    get_vec_literals(|evidence: &PatternEvidence| &evidence.any_literals),
                );
            }
        }

        // 转换为 Vec 并过滤短字面量
        let known_any_vec = finalize_known_literals(
            known_any_literals,
            literal_interner,
            ANY_LITERAL_MIN_LENGTH_GLOBAL,
        );

        AnyIndexBuildResult {
            any_index,
            known_any_literals: known_any_vec,
            known_any_by_scope,
        }
    }
}
