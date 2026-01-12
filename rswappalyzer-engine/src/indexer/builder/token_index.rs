//! Token 索引构建器
//! 负责构建 token 相关的反向索引

use crate::{CompiledTechRule, PruneScope};
use rustc_hash::{FxHashMap, FxHashSet};

/// Token 索引构建结果
#[derive(Debug, Clone)]
pub struct TokenIndexBuildResult {
    /// token -> scope -> techs 反向索引
    pub evidence_index: FxHashMap<String, FxHashMap<PruneScope, FxHashSet<String>>>,
    /// 全局已知 token 集合
    pub known_tokens: FxHashSet<String>,
    /// 按 scope 分组的 known_tokens
    pub known_tokens_by_scope: FxHashMap<PruneScope, FxHashSet<String>>,
    /// 无证据规则索引
    pub no_evidence_index: FxHashMap<PruneScope, FxHashSet<String>>,
}

/// Token 索引构建器
pub struct TokenIndexBuilder;

impl TokenIndexBuilder {
    /// 构建 Token 相关索引
    pub fn build(
        compiled_tech: &FxHashMap<String, CompiledTechRule>,
    ) -> TokenIndexBuildResult {
        // 1. 构建证据索引和无证据索引
        let (evidence_index, no_evidence_index) = Self::build_evidence_indexes(compiled_tech);

        // 2. 构建 known_tokens 和 known_tokens_by_scope
        let (known_tokens, known_tokens_by_scope) = Self::build_known_tokens(&evidence_index);

        TokenIndexBuildResult {
            evidence_index,
            known_tokens,
            known_tokens_by_scope,
            no_evidence_index,
        }
    }

    /// 构建证据索引和无证据索引
    fn build_evidence_indexes(
        compiled_tech: &FxHashMap<String, CompiledTechRule>,
    ) -> (
        FxHashMap<String, FxHashMap<PruneScope, FxHashSet<String>>>,
        FxHashMap<PruneScope, FxHashSet<String>>,
    ) {
        let mut evidence_index = FxHashMap::default();
        let mut no_evidence_index = FxHashMap::default();

        // 遍历所有技术规则，填充索引
        for (tech_name, tech_rule) in compiled_tech {
            // 填充内容型规则的证据索引
            Self::fill_evidence_index_with_scope(
                tech_name,
                tech_rule.url_patterns.as_ref(),
                PruneScope::Url,
                &mut evidence_index,
            );
            Self::fill_evidence_index_with_scope(
                tech_name,
                tech_rule.html_patterns.as_ref(),
                PruneScope::Html,
                &mut evidence_index,
            );
            Self::fill_evidence_index_with_scope(
                tech_name,
                tech_rule.script_patterns.as_ref(),
                PruneScope::Script,
                &mut evidence_index,
            );

            // 填充KV型规则的证据索引
            Self::fill_evidence_index_for_keyed_with_scope(
                tech_name,
                tech_rule.meta_patterns.as_ref(),
                PruneScope::Meta,
                &mut evidence_index,
            );
            Self::fill_evidence_index_for_keyed_with_scope(
                tech_name,
                tech_rule.header_patterns.as_ref(),
                PruneScope::Header,
                &mut evidence_index,
            );
            Self::fill_evidence_index_for_keyed_with_scope(
                tech_name,
                tech_rule.cookie_patterns.as_ref(),
                PruneScope::Cookie,
                &mut evidence_index,
            );

            // 填充无证据索引
            Self::fill_no_evidence_index_with_scope(tech_name, tech_rule, &mut no_evidence_index);
        }

        (evidence_index, no_evidence_index)
    }

    /// 构建 known_tokens 和 known_tokens_by_scope
    fn build_known_tokens(
        evidence_index: &FxHashMap<String, FxHashMap<PruneScope, FxHashSet<String>>>,
    ) -> (FxHashSet<String>, FxHashMap<PruneScope, FxHashSet<String>>) {
        let mut known_tokens = FxHashSet::default();
        let mut known_tokens_by_scope = FxHashMap::default();

        for (token, scope_to_techs) in evidence_index {
            // 填充全局 known_tokens
            known_tokens.insert(token.clone());

            // 填充按 scope 的 known_tokens_by_scope
            for (scope, _techs) in scope_to_techs {
                known_tokens_by_scope
                    .entry(*scope)
                    .or_insert_with(FxHashSet::default)
                    .insert(token.clone());
            }
        }

        (known_tokens, known_tokens_by_scope)
    }

    fn fill_evidence_index_with_scope(
        tech_name: &String,
        patterns: Option<&Vec<crate::CompiledPattern>>,
        scope: PruneScope,
        evidence_map: &mut FxHashMap<String, FxHashMap<PruneScope, FxHashSet<String>>>,
    ) {
        let Some(pats) = patterns else { return };

        for pat in pats {
            let mut evidence_set = FxHashSet::default();

            // 阶段1：提取 token 证据
            if let Some(tokens) = &pat.exec.match_gate.require_tokens {
                evidence_set.extend(tokens.iter().cloned());
            }

            // 阶段2：提取原始字面量证据（token 索引中也会包含，但 literal 索引会单独处理）
            if let Some(literal) = &pat.exec.match_gate.require_literal {
                evidence_set.insert(literal.clone());
            }

            // 阶段3：提取结构any证据
            if let Some(any_list) = &pat.exec.match_gate.require_any_literal {
                evidence_set.extend(any_list.iter().cloned());
            }

            if !evidence_set.is_empty() {
                for evidence in evidence_set {
                    evidence_map
                        .entry(evidence.clone())
                        .or_default()
                        .entry(scope)
                        .or_default()
                        .insert(tech_name.clone());
                }
            }
        }
    }

    fn fill_evidence_index_for_keyed_with_scope(
        tech_name: &String,
        keyed_patterns: Option<&FxHashMap<String, Vec<crate::CompiledPattern>>>,
        scope: PruneScope,
        evidence_map: &mut FxHashMap<String, FxHashMap<PruneScope, FxHashSet<String>>>,
    ) {
        let Some(keyed_pats) = keyed_patterns else { return };

        for (_key, pats) in keyed_pats {
            for pat in pats {
                let mut evidence_set = FxHashSet::default();

                if let Some(tokens) = &pat.exec.match_gate.require_tokens {
                    evidence_set.extend(tokens.iter().cloned());
                }
                if let Some(literal) = &pat.exec.match_gate.require_literal {
                    evidence_set.insert(literal.clone());
                }
                if let Some(any_list) = &pat.exec.match_gate.require_any_literal {
                    evidence_set.extend(any_list.iter().cloned());
                }

                if !evidence_set.is_empty() {
                    for evidence in evidence_set {
                        evidence_map
                            .entry(evidence.clone())
                            .or_default()
                            .entry(scope)
                            .or_default()
                            .insert(tech_name.clone());
                    }
                }
            }
        }
    }

    fn fill_no_evidence_index_with_scope(
        tech_name: &String,
        rule: &CompiledTechRule,
        no_evidence_map: &mut FxHashMap<PruneScope, FxHashSet<String>>,
    ) {
        // 判断是否为无证据规则
        let is_no_evidence = |cp: &crate::CompiledPattern| cp.exec.match_gate.require_tokens.is_none();

        // 检查各作用域规则
        if rule
            .url_patterns
            .as_ref()
            .map_or(false, |p| p.iter().any(is_no_evidence))
        {
            no_evidence_map
                .entry(PruneScope::Url)
                .or_default()
                .insert(tech_name.clone());
        }
        if rule
            .html_patterns
            .as_ref()
            .map_or(false, |p| p.iter().any(is_no_evidence))
        {
            no_evidence_map
                .entry(PruneScope::Html)
                .or_default()
                .insert(tech_name.clone());
        }
        if rule
            .script_patterns
            .as_ref()
            .map_or(false, |p| p.iter().any(is_no_evidence))
        {
            no_evidence_map
                .entry(PruneScope::Script)
                .or_default()
                .insert(tech_name.clone());
        }
        if rule
            .meta_patterns
            .as_ref()
            .map_or(false, |k| k.values().any(|p| p.iter().any(is_no_evidence)))
        {
            no_evidence_map
                .entry(PruneScope::Meta)
                .or_default()
                .insert(tech_name.clone());
        }
        if rule
            .header_patterns
            .as_ref()
            .map_or(false, |k| k.values().any(|p| p.iter().any(is_no_evidence)))
        {
            no_evidence_map
                .entry(PruneScope::Header)
                .or_default()
                .insert(tech_name.clone());
        }
        if rule
            .cookie_patterns
            .as_ref()
            .map_or(false, |k| k.values().any(|p| p.iter().any(is_no_evidence)))
        {
            no_evidence_map
                .entry(PruneScope::Cookie)
                .or_default()
                .insert(tech_name.clone());
        }
    }
}