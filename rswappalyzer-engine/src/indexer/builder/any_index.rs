//! Any 索引构建器
//! 负责构建 Stage3 any literal 相关的反向索引

use crate::{CompiledPattern, CompiledTechRule, PruneScope};
use rustc_hash::{FxHashMap, FxHashSet};

// 核心：定义Any literal长度限制常量（支持空值/短字面量兼容）
/// 内容型规则（URL/HTML/Script）的最小any literal长度（空值/短于该值会被过滤）
const ANY_LITERAL_MIN_LENGTH_CONTENT: usize = 3;
/// KV型规则（Meta/Header/Cookie）的最小any literal长度（空值/短于该值会被过滤）
const ANY_LITERAL_MIN_LENGTH_KEYED: usize = 3;
/// 全局known_any_literals的最小长度（构建AC自动机时过滤）
const ANY_LITERAL_MIN_LENGTH_GLOBAL: usize = 3;

/// Any 索引构建结果
#[derive(Debug, Clone)]
pub struct AnyIndexBuildResult {
    /// any_literal -> scope -> techs 反向索引
    pub any_index: FxHashMap<String, FxHashMap<PruneScope, FxHashSet<String>>>,
    /// 全局已知 any literal 列表（Vec 便于构建 AC）
    pub known_any_literals: Vec<String>,
    /// 按 scope 分组的 known_any_literals
    pub known_any_by_scope: FxHashMap<PruneScope, FxHashSet<String>>,
}

/// Any 索引构建器
pub struct AnyIndexBuilder;

impl AnyIndexBuilder {
    /// 构建 Any literal 相关索引
    pub fn build(
        compiled_tech: &FxHashMap<String, CompiledTechRule>,
    ) -> AnyIndexBuildResult {
        let mut any_index = FxHashMap::default();
        let mut known_any_literals = FxHashSet::default();
        let mut known_any_by_scope = FxHashMap::default();

        // 遍历所有技术规则，提取 any literal 证据
        for (tech_name, tech_rule) in compiled_tech {
            // 内容型规则
            Self::extract_any_from_patterns(
                tech_name,
                tech_rule.url_patterns.as_ref(),
                PruneScope::Url,
                &mut any_index,
                &mut known_any_literals,
                &mut known_any_by_scope,
            );
            Self::extract_any_from_patterns(
                tech_name,
                tech_rule.html_patterns.as_ref(),
                PruneScope::Html,
                &mut any_index,
                &mut known_any_literals,
                &mut known_any_by_scope,
            );
            Self::extract_any_from_patterns(
                tech_name,
                tech_rule.script_patterns.as_ref(),
                PruneScope::Script,
                &mut any_index,
                &mut known_any_literals,
                &mut known_any_by_scope,
            );

            // KV 型规则
            Self::extract_any_from_keyed_patterns(
                tech_name,
                tech_rule.meta_patterns.as_ref(),
                PruneScope::Meta,
                &mut any_index,
                &mut known_any_literals,
                &mut known_any_by_scope,
            );
            Self::extract_any_from_keyed_patterns(
                tech_name,
                tech_rule.header_patterns.as_ref(),
                PruneScope::Header,
                &mut any_index,
                &mut known_any_literals,
                &mut known_any_by_scope,
            );
            Self::extract_any_from_keyed_patterns(
                tech_name,
                tech_rule.cookie_patterns.as_ref(),
                PruneScope::Cookie,
                &mut any_index,
                &mut known_any_literals,
                &mut known_any_by_scope,
            );
        }

        // 转换为 Vec，使用常量过滤短字面量
        let known_any_vec: Vec<String> = known_any_literals
            .into_iter()
            .filter(|lit| lit.len() >= ANY_LITERAL_MIN_LENGTH_GLOBAL)
            .collect();

        AnyIndexBuildResult {
            any_index,
            known_any_literals: known_any_vec,
            known_any_by_scope,
        }
    }

    /// 从内容型模式中提取 any literal
    fn extract_any_from_patterns(
        tech_name: &String,
        patterns: Option<&Vec<CompiledPattern>>,
        scope: PruneScope,
        any_index: &mut FxHashMap<String, FxHashMap<PruneScope, FxHashSet<String>>>,
        known_any_literals: &mut FxHashSet<String>,
        known_any_by_scope: &mut FxHashMap<PruneScope, FxHashSet<String>>,
    ) {
        let Some(pats) = patterns else { return };

        for pat in pats {
            if let Some(any_list) = &pat.exec.match_gate.require_any_literal {
                for any_literal in any_list {
                    // 使用常量过滤短字面量（空值/长度<4会被过滤）
                    if any_literal.len() < ANY_LITERAL_MIN_LENGTH_CONTENT {
                        continue;
                    }
                    
                    // 更新 any 反向索引
                    any_index
                        .entry(any_literal.clone())
                        .or_default()
                        .entry(scope)
                        .or_default()
                        .insert(tech_name.clone());
                    
                    // 更新 known_any_literals
                    known_any_literals.insert(any_literal.clone());
                    known_any_by_scope
                        .entry(scope)
                        .or_default()
                        .insert(any_literal.clone());
                }
            }
        }
    }

    /// 从 KV 型模式中提取 any literal
    fn extract_any_from_keyed_patterns(
        tech_name: &String,
        keyed_patterns: Option<&FxHashMap<String, Vec<CompiledPattern>>>,
        scope: PruneScope,
        any_index: &mut FxHashMap<String, FxHashMap<PruneScope, FxHashSet<String>>>,
        known_any_literals: &mut FxHashSet<String>,
        known_any_by_scope: &mut FxHashMap<PruneScope, FxHashSet<String>>,
    ) {
        let Some(keyed_pats) = keyed_patterns else { return };

        for (_key, pats) in keyed_pats {
            for pat in pats {
                if let Some(any_list) = &pat.exec.match_gate.require_any_literal {
                    for any_literal in any_list {
                        // 使用常量过滤短字面量（空值/长度<4会被过滤）
                        if any_literal.len() < ANY_LITERAL_MIN_LENGTH_KEYED {
                            continue;
                        }
                        
                        any_index
                            .entry(any_literal.clone())
                            .or_default()
                            .entry(scope)
                            .or_default()
                            .insert(tech_name.clone());
                        
                        known_any_literals.insert(any_literal.clone());
                        known_any_by_scope
                            .entry(scope)
                            .or_default()
                            .insert(any_literal.clone());
                    }
                }
            }
        }
    }
}