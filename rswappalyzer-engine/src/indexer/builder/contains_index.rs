//! Contains 索引构建器
//! 负责构建匹配层 Contains 相关的索引

use crate::{
    builder::index_utils::{
        finalize_known_literals, get_single_literal, process_patterns, CONTENT_SCOPES, KEYED_SCOPES,
    },
    compiled::{LiteralId, LiteralInterner, PatternEvidence, TechId, TechInterner},
    CompiledTechRule, Scope,
};
use rustc_hash::{FxHashMap, FxHashSet};

/// Contains 最小长度限制
const CONTAINS_MIN_LENGTH: usize = 2;

/// Contains 索引构建结果
#[derive(Debug, Clone)]
pub struct ContainsIndexBuildResult {
    pub contains_index: FxHashMap<LiteralId, FxHashMap<Scope, FxHashSet<TechId>>>,
    pub known_contains: Vec<LiteralId>,
    pub known_contains_by_scope: FxHashMap<Scope, FxHashSet<LiteralId>>,
}

/// Contains 索引构建器
pub struct ContainsIndexBuilder;

impl ContainsIndexBuilder {
    /// 构建 Contains 相关索引
    pub fn build(
        compiled_tech: &FxHashMap<String, CompiledTechRule>,
        literal_interner: &mut LiteralInterner,
        tech_interner: &mut TechInterner,
    ) -> ContainsIndexBuildResult {
        let mut contains_index = FxHashMap::default();
        let mut known_contains = FxHashSet::default();
        let mut known_contains_by_scope = FxHashMap::default();

        // 遍历所有技术规则
        for (tech_name, tech_rule) in compiled_tech {
            let tech_id = tech_interner.get_or_insert(tech_name);

            // 处理内容型规则（URL/HTML/Script）
            for (_name, get_patterns, scope) in CONTENT_SCOPES {
                let patterns = get_patterns(tech_rule);
                process_patterns(
                    tech_id,
                    patterns,
                    *scope,
                    literal_interner,
                    CONTAINS_MIN_LENGTH,
                    &mut contains_index,
                    &mut known_contains,
                    &mut known_contains_by_scope,
                    get_single_literal(|evidence: &PatternEvidence| Some(&evidence.contains)),
                );
            }

            // 处理KV型规则（Meta/Header/Cookie）
            for (_name, get_patterns, scope) in KEYED_SCOPES {
                let patterns = get_patterns(tech_rule);
                process_patterns(
                    tech_id,
                    patterns,
                    *scope,
                    literal_interner,
                    CONTAINS_MIN_LENGTH,
                    &mut contains_index,
                    &mut known_contains,
                    &mut known_contains_by_scope,
                    get_single_literal(|evidence: &PatternEvidence| Some(&evidence.contains)),
                );
            }
        }

        // 最终化已知字面量
        let known_contains_vec =
            finalize_known_literals(known_contains, literal_interner, CONTAINS_MIN_LENGTH);

        ContainsIndexBuildResult {
            contains_index,
            known_contains: known_contains_vec,
            known_contains_by_scope,
        }
    }
}