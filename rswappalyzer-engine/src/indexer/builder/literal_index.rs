//! Literal 索引构建器
//! 负责构建 Stage2 literal 相关的反向索引

use crate::{CompiledPattern, CompiledTechRule, PruneScope};
use rustc_hash::{FxHashMap, FxHashSet};

// 核心：定义长度限制常量（支持空值/短字面量兼容）
/// 内容型规则（URL/HTML/Script）的最小literal长度（空值/短于该值会被过滤）
const LITERAL_MIN_LENGTH_CONTENT: usize = 2;
/// KV型规则（Meta/Header/Cookie）的最小literal长度（空值/短于该值会被过滤）
const LITERAL_MIN_LENGTH_KEYED: usize = 2;
/// 全局known_literals的最小长度（构建AC自动机时过滤）
const LITERAL_MIN_LENGTH_GLOBAL: usize = 2;

/// Literal 索引构建结果
#[derive(Debug, Clone)]
pub struct LiteralIndexBuildResult {
    /// literal -> scope -> techs 反向索引
    pub literal_index: FxHashMap<String, FxHashMap<PruneScope, FxHashSet<String>>>,
    /// 全局已知 literal 列表（Vec 便于构建 AC）
    pub known_literals: Vec<String>,
    /// 按 scope 分组的 known_literals
    pub known_literals_by_scope: FxHashMap<PruneScope, FxHashSet<String>>,
}

/// Literal 索引构建器
pub struct LiteralIndexBuilder;

impl LiteralIndexBuilder {
    /// 构建 Literal 相关索引
    pub fn build(
        compiled_tech: &FxHashMap<String, CompiledTechRule>,
    ) -> LiteralIndexBuildResult {
        let mut literal_index = FxHashMap::default();
        let mut known_literals = FxHashSet::default();
        let mut known_literals_by_scope = FxHashMap::default();

        // 遍历所有技术规则，提取 literal 证据
        for (tech_name, tech_rule) in compiled_tech {
            // 内容型规则（URL/HTML/Script）
            Self::extract_literals_from_patterns(
                tech_name,
                tech_rule.url_patterns.as_ref(),
                PruneScope::Url,
                &mut literal_index,
                &mut known_literals,
                &mut known_literals_by_scope,
            );
            Self::extract_literals_from_patterns(
                tech_name,
                tech_rule.html_patterns.as_ref(),
                PruneScope::Html,
                &mut literal_index,
                &mut known_literals,
                &mut known_literals_by_scope,
            );
            Self::extract_literals_from_patterns(
                tech_name,
                tech_rule.script_patterns.as_ref(),
                PruneScope::Script,
                &mut literal_index,
                &mut known_literals,
                &mut known_literals_by_scope,
            );

            // KV 型规则（Meta/Header/Cookie）
            Self::extract_literals_from_keyed_patterns(
                tech_name,
                tech_rule.meta_patterns.as_ref(),
                PruneScope::Meta,
                &mut literal_index,
                &mut known_literals,
                &mut known_literals_by_scope,
            );
            Self::extract_literals_from_keyed_patterns(
                tech_name,
                tech_rule.header_patterns.as_ref(),
                PruneScope::Header,
                &mut literal_index,
                &mut known_literals,
                &mut known_literals_by_scope,
            );
            Self::extract_literals_from_keyed_patterns(
                tech_name,
                tech_rule.cookie_patterns.as_ref(),
                PruneScope::Cookie,
                &mut literal_index,
                &mut known_literals,
                &mut known_literals_by_scope,
            );
        }

        // 转换为 Vec（便于构建 AC），使用常量过滤短字面量
        let known_literals_vec: Vec<String> = known_literals
            .into_iter()
            .filter(|lit| lit.len() >= LITERAL_MIN_LENGTH_GLOBAL)
            .collect();

        LiteralIndexBuildResult {
            literal_index,
            known_literals: known_literals_vec,
            known_literals_by_scope,
        }
    }

    /// 从内容型模式中提取 literal
    fn extract_literals_from_patterns(
        tech_name: &String,
        patterns: Option<&Vec<CompiledPattern>>,
        scope: PruneScope,
        literal_index: &mut FxHashMap<String, FxHashMap<PruneScope, FxHashSet<String>>>,
        known_literals: &mut FxHashSet<String>,
        known_literals_by_scope: &mut FxHashMap<PruneScope, FxHashSet<String>>,
    ) {
        let Some(pats) = patterns else { return };

        for pat in pats {
            if let Some(literal) = &pat.exec.match_gate.require_literal {
                // 使用常量过滤短字面量（空值/长度<2会被过滤）
                if literal.len() < LITERAL_MIN_LENGTH_CONTENT {
                    continue;
                }
                
                // 更新 literal 反向索引
                literal_index
                    .entry(literal.clone())
                    .or_default()
                    .entry(scope)
                    .or_default()
                    .insert(tech_name.clone());
                
                // 更新 known_literals
                known_literals.insert(literal.clone());
                known_literals_by_scope
                    .entry(scope)
                    .or_default()
                    .insert(literal.clone());
            }
        }
    }

    /// 从 KV 型模式中提取 literal
    fn extract_literals_from_keyed_patterns(
        tech_name: &String,
        keyed_patterns: Option<&FxHashMap<String, Vec<CompiledPattern>>>,
        scope: PruneScope,
        literal_index: &mut FxHashMap<String, FxHashMap<PruneScope, FxHashSet<String>>>,
        known_literals: &mut FxHashSet<String>,
        known_literals_by_scope: &mut FxHashMap<PruneScope, FxHashSet<String>>,
    ) {
        let Some(keyed_pats) = keyed_patterns else { return };

        for (_key, pats) in keyed_pats {
            for pat in pats {
                if let Some(literal) = &pat.exec.match_gate.require_literal {
                    // 使用常量过滤短字面量（空值/长度<2会被过滤）
                    if literal.len() < LITERAL_MIN_LENGTH_KEYED {
                        continue;
                    }
                    
                    literal_index
                        .entry(literal.clone())
                        .or_default()
                        .entry(scope)
                        .or_default()
                        .insert(tech_name.clone());
                    
                    known_literals.insert(literal.clone());
                    known_literals_by_scope
                        .entry(scope)
                        .or_default()
                        .insert(literal.clone());
                }
            }
        }
    }
}