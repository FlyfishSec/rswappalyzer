//! 规则索引器（主入口）
//! 负责协调各子索引构建器，生成最终的编译规则库

use crate::{
    CompiledRuleLibrary, CompiledTechRule, CoreResult, PruneScope, RuleLibraryIndex, ScopedIndexedRule, core::{MatchScope, TechBasicInfo}, indexer::builder::{any_index::AnyIndexBuilder, literal_index::LiteralIndexBuilder, token_index::TokenIndexBuilder}
};
use rustc_hash::{FxHashMap, FxHashSet};

/// 技术规则构建器（临时存储）
#[derive(Debug, Clone, Default)]
struct BuiltTechRule {
    tech_info: TechBasicInfo,
    url_rules: Vec<crate::indexer::index_rules::CommonIndexedRule>,
    html_rules: Vec<crate::indexer::index_rules::CommonIndexedRule>,
    script_rules: Vec<crate::indexer::index_rules::CommonIndexedRule>,
    meta_rules: FxHashMap<String, Vec<crate::indexer::index_rules::CommonIndexedRule>>,
    header_rules: FxHashMap<String, Vec<crate::indexer::index_rules::CommonIndexedRule>>,
    cookie_rules: FxHashMap<String, Vec<crate::indexer::index_rules::CommonIndexedRule>>,
}

/// 技术规则构建器（生命周期内）
struct TechRuleBuilder<'a> {
    tech_info_map: &'a FxHashMap<String, TechBasicInfo>,
    tech_rules: FxHashMap<String, BuiltTechRule>,
}

impl<'a> TechRuleBuilder<'a> {
    fn new(tech_info_map: &'a FxHashMap<String, TechBasicInfo>) -> Self {
        Self {
            tech_info_map,
            tech_rules: FxHashMap::default(),
        }
    }

    fn add_scoped_rule(
        &mut self,
        scope: &MatchScope,
        scoped_rule: &ScopedIndexedRule,
    ) {
        let common = scoped_rule.common();
        let tech_name = &common.tech;

        let rule = self
            .tech_rules
            .entry(tech_name.clone())
            .or_insert_with(|| BuiltTechRule {
                tech_info: self
                    .tech_info_map
                    .get(tech_name)
                    .cloned()
                    .unwrap_or_default(),
                ..BuiltTechRule::default()
            });

        match (scope, scoped_rule) {
            (MatchScope::Url, _) => rule.url_rules.push(common.clone()),
            (MatchScope::Html, _) => rule.html_rules.push(common.clone()),
            (MatchScope::Script | MatchScope::ScriptSrc, _) => {
                rule.script_rules.push(common.clone())
            }
            (MatchScope::Meta, ScopedIndexedRule::KV { key, .. }) => rule
                .meta_rules
                .entry(key.clone())
                .or_default()
                .push(common.clone()),
            (MatchScope::Header, ScopedIndexedRule::KV { key, .. }) => rule
                .header_rules
                .entry(key.clone())
                .or_default()
                .push(common.clone()),
            (MatchScope::Cookie, ScopedIndexedRule::KV { key, .. }) => rule
                .cookie_rules
                .entry(key.clone())
                .or_default()
                .push(common.clone()),
            _ => eprintln!(
                "Tech [{}] has invalid rule type for scope {}",
                tech_name, scope
            ),
        }
    }

    fn into_iter(self) -> impl Iterator<Item = (String, BuiltTechRule)> {
        self.tech_rules.into_iter()
    }
}

/// 规则索引器（主结构体）
#[derive(Debug, Clone, Default)]
pub struct RuleIndexer;

impl RuleIndexer {
    /// 使用默认分类文件构建编译规则库
    pub fn build_compiled_library_with_default_category(
        index: &RuleLibraryIndex,
    ) -> CoreResult<CompiledRuleLibrary> {
        Self::build_compiled_library(index, Some("data/categories_data.json"))
    }

    /// 构建编译规则库
    pub fn build_compiled_library(
        index: &RuleLibraryIndex,
        category_json_path: Option<&str>,
    ) -> CoreResult<CompiledRuleLibrary> {
        // ========== 1. 构建临时技术规则 ==========
        let mut builder = TechRuleBuilder::new(&index.tech_info_map);
        for (scope, rules) in &index.rules {
            rules.iter().for_each(|r| builder.add_scoped_rule(scope, r));
        }

        // ========== 2. 编译为 CompiledTechRule ==========
        let mut compiled_tech = FxHashMap::default();
        let mut compiled_meta = FxHashMap::default();

        for (name, rule) in builder.into_iter() {
            let implies = rule.tech_info.implies.clone().unwrap_or_default();
            compiled_tech.insert(
                name.clone(),
                CompiledTechRule {
                    name: name.clone(),
                    url_patterns: Self::compile_content_patterns(&rule.url_rules, PruneScope::Url),
                    html_patterns: Self::compile_content_patterns(
                        &rule.html_rules,
                        PruneScope::Html,
                    ),
                    script_patterns: Self::compile_content_patterns(
                        &rule.script_rules,
                        PruneScope::Script,
                    ),
                    meta_patterns: Self::compile_keyed_patterns(&rule.meta_rules, PruneScope::Meta),
                    header_patterns: Self::compile_keyed_patterns(
                        &rule.header_rules,
                        PruneScope::Header,
                    ),
                    cookie_patterns: Self::compile_keyed_patterns(
                        &rule.cookie_rules,
                        PruneScope::Cookie,
                    ),
                    category_ids: rule.tech_info.category_ids.clone(),
                    implies,
                },
            );
            compiled_meta.insert(name, rule.tech_info);
        }

        // ========== 3. 加载分类映射 ==========
        let category_map = match category_json_path {
            Some(path) => Self::load_category_map(path),
            None => FxHashMap::default(),
        };

        // ========== 4. 调用各子索引构建器 ==========
        // Token 索引
        let token_index = TokenIndexBuilder::build(&compiled_tech);
        // Literal 索引
        let literal_index = LiteralIndexBuilder::build(&compiled_tech);
        //println!("Header维度是否包含iis: {}", literal_index.known_literals_by_scope.get(&PruneScope::Header).map_or(false, |s| s.contains("iis")));
        //std::process::exit(1);

        // Any 索引
        let any_index = AnyIndexBuilder::build(&compiled_tech);

        // ========== 5. 组装最终的编译规则库 ==========
        Ok(CompiledRuleLibrary {
            tech_patterns: compiled_tech,
            category_map,
            tech_meta: compiled_meta,
            // Token 索引字段
            evidence_index: token_index.evidence_index,
            known_tokens: token_index.known_tokens,
            known_tokens_by_scope: token_index.known_tokens_by_scope,
            no_evidence_index: token_index.no_evidence_index,
            // Literal 索引字段
            literal_index: literal_index.literal_index,
            known_literals: literal_index.known_literals,
            known_literals_by_scope: literal_index.known_literals_by_scope,
            // Any 索引字段
            any_index: any_index.any_index,
            known_any_literals: any_index.known_any_literals,
            known_any_by_scope: any_index.known_any_by_scope,
        })
    }

    pub fn load_category_map(json_path: &str) -> FxHashMap<u32, String> {
        let json_content = match std::fs::read_to_string(json_path) {
            Ok(c) => c,
            Err(e) => {
                log::debug!(
                    "Category map file read failed, fallback to empty map | Path: {} | Error: {}",
                    json_path,
                    e
                );
                return FxHashMap::default();
            }
        };

        let category_entries: crate::core::CategoryJsonRoot = match serde_json::from_str(&json_content) {
            Ok(v) => v,
            Err(e) => {
                log::debug!(
                    "Category map JSON parse failed, fallback to empty map | Error: {}",
                    e
                );
                return FxHashMap::default();
            }
        };

        let mut map = FxHashMap::default();
        for (category_id_str, entry) in category_entries {
            if entry.name.is_empty() {
                continue;
            }

            match category_id_str.parse::<u32>() {
                Ok(id) => {
                    map.insert(id, entry.name);
                }
                Err(e) => {
                    log::debug!(
                        "Invalid category ID, skipped | ID: {} | Error: {}",
                        category_id_str,
                        e
                    );
                }
            }
        }

        map
    }

    fn compile_content_patterns(
        rules: &[crate::indexer::index_rules::CommonIndexedRule],
        scope: PruneScope,
    ) -> Option<Vec<crate::CompiledPattern>> {
        let mut pats = Vec::new();

        for r in rules {
            let matcher = crate::indexer::matcher::Matcher::from_match_type_lazy(&r.match_type, &r.pattern);
            let matcher_spec = matcher.to_spec();

            let min_evidence_meta = Self::extract_min_evidence_with_meta(&matcher);
            let structural_prereq = crate::StructuralPrereq::from_matcher(&matcher);

            let match_gate = crate::indexer::matcher::fold_to_match_gate(min_evidence_meta, structural_prereq);

            pats.push(crate::CompiledPattern {
                scope,
                index_key: String::new(),
                exec: crate::ExecutablePattern {
                    matcher: matcher_spec,
                    matcher_cache: once_cell::sync::OnceCell::new(),
                    match_gate,
                    confidence: 100,
                    version_template: r.pattern.version_template.clone(),
                },
            });
        }

        (!pats.is_empty()).then_some(pats)
    }

    fn compile_keyed_patterns(
        rules: &FxHashMap<String, Vec<crate::indexer::index_rules::CommonIndexedRule>>,
        scope: PruneScope,
    ) -> Option<FxHashMap<String, Vec<crate::CompiledPattern>>> {
        let mut pats = FxHashMap::default();

        for (k, rs) in rules {
            let mut rule_pats = Vec::new();

            for r in rs {
                let matcher = crate::indexer::matcher::Matcher::from_match_type_lazy(&r.match_type, &r.pattern);
                let matcher_spec = matcher.to_spec();

                let min_evidence_meta = Self::extract_min_evidence_with_meta(&matcher);
                let structural_prereq = crate::StructuralPrereq::from_matcher(&matcher);

                let match_gate = crate::indexer::matcher::fold_to_match_gate(min_evidence_meta, structural_prereq);

                rule_pats.push(crate::CompiledPattern {
                    scope,
                    index_key: k.clone(),
                    exec: crate::ExecutablePattern {
                        matcher: matcher_spec,
                        matcher_cache: once_cell::sync::OnceCell::new(),
                        match_gate,
                        confidence: 100,
                        version_template: r.pattern.version_template.clone(),
                    },
                });
            }

            if !rule_pats.is_empty() {
                pats.insert(k.to_lowercase(), rule_pats);
            }
        }

        (!pats.is_empty()).then_some(pats)
    }

    #[inline(always)]
    fn extract_min_evidence_with_meta(matcher: &crate::indexer::matcher::Matcher) -> crate::min_evidence::MinEvidenceMeta {
        match matcher {
            crate::indexer::matcher::Matcher::Contains(s) => {
                let literal = crate::utils::safe_lower::safe_lowercase(s.as_str());
                let source_len = literal.len();
                let tokens = if literal.len() > 2 {
                    crate::pruner::tokenizer::extract_atomic_tokens(&literal)
                } else {
                    FxHashSet::default()
                };
                crate::min_evidence::MinEvidenceMeta {
                    tokens,
                    source_len,
                    source_literal: literal,
                }
            }
            crate::indexer::matcher::Matcher::LazyRegex { pattern, .. } => {
                let min_evidence = crate::pruner::min_evidence::extract_min_evidence_meta(pattern.as_str());
                crate::min_evidence::MinEvidenceMeta {
                    tokens: min_evidence.tokens,
                    source_len: min_evidence.source_len,
                    source_literal: min_evidence.source_literal,
                }
            }
            crate::indexer::matcher::Matcher::Exists => crate::min_evidence::MinEvidenceMeta {
                tokens: FxHashSet::default(),
                source_len: 0,
                source_literal: String::new(),
            },
        }
    }
}