//! Literal 索引构建器
//! 负责构建 literals 反向索引

use crate::{
    CompiledTechRule, Scope, builder::index_utils::{
        CONTENT_SCOPES, KEYED_SCOPES, finalize_known_literals, get_vec_literals, process_patterns
    }, compiled::{LiteralId, LiteralInterner, PatternEvidence, TechId, TechInterner}
};
use rustc_hash::{FxHashMap, FxHashSet};

// 核心：定义长度限制常量
const LITERAL_MIN_LENGTH_CONTENT: usize = 2;
const LITERAL_MIN_LENGTH_KEYED: usize = 2;
const LITERAL_MIN_LENGTH_GLOBAL: usize = 2;

/// Literal 索引构建结果
#[derive(Debug, Clone)]
pub struct LiteralIndexBuildResult {
    pub literal_index: FxHashMap<LiteralId, FxHashMap<Scope, FxHashSet<TechId>>>,
    pub known_literals: Vec<LiteralId>,
    pub known_literals_by_scope: FxHashMap<Scope, FxHashSet<LiteralId>>,
}

/// Literal 索引构建器
pub struct LiteralIndexBuilder;

impl LiteralIndexBuilder {
    /// 构建 Literal 相关索引
    pub fn build(
        compiled_tech: &FxHashMap<String, CompiledTechRule>,
        literal_interner: &mut LiteralInterner,
        tech_interner: &mut TechInterner,
    ) -> LiteralIndexBuildResult {
        let mut literal_index = FxHashMap::default();
        let mut known_literals = FxHashSet::default();
        let mut known_literals_by_scope = FxHashMap::default();

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
                    LITERAL_MIN_LENGTH_CONTENT,
                    &mut literal_index,
                    &mut known_literals,
                    &mut known_literals_by_scope,
                    get_vec_literals(|evidence: &PatternEvidence| &evidence.literals),
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
                    LITERAL_MIN_LENGTH_KEYED,
                    &mut literal_index,
                    &mut known_literals,
                    &mut known_literals_by_scope,
                    get_vec_literals(|evidence: &PatternEvidence| &evidence.literals),
                );
            }
        }

        // 最终化已知字面量
        let known_literals_vec =
            finalize_known_literals(known_literals, literal_interner, LITERAL_MIN_LENGTH_GLOBAL);

        LiteralIndexBuildResult {
            literal_index,
            known_literals: known_literals_vec,
            known_literals_by_scope,
        }
    }
}
