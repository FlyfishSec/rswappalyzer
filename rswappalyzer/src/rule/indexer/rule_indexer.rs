//! 规则索引构建器
use rustc_hash::FxHashMap;
use rustc_hash::FxHashSet;
use serde::{Deserialize, Serialize};

use crate::rule::core::RuleLibrary;
use crate::rule::core::TechBasicInfo;
use crate::rule::indexer::index_pattern::ExecutablePattern;
use crate::rule::indexer::index_pattern::MatchGate;
use crate::rule::indexer::index_pattern::StructuralPrereq;
use crate::rule::indexer::index_pattern::fold_to_match_gate;
use crate::rule::indexer::index_pattern::{
    CompiledPattern, CompiledRuleLibrary, CompiledTechRule, Matcher, PruneStrategy,
};
use crate::rule::indexer::indexed_rule::{CommonIndexedRule, ScopedIndexedRule};
use crate::rule::indexer::scope::{MatchRuleSet, MatchScope};
use crate::utils::regex_filter;
use crate::utils::regex_filter::extract_evidence::safe_lowercase;
use crate::utils::regex_filter::scope_pruner::PruneScope;
use crate::RswResult;
use log::warn;
//use std::collections::HashMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleLibraryIndex {
    pub rules: FxHashMap<MatchScope, Vec<ScopedIndexedRule>>,
    pub tech_info_map: FxHashMap<String, TechBasicInfo>,
}

impl RuleLibraryIndex {
    pub fn from_rule_library(rule_library: &RuleLibrary) -> RswResult<Self> {
        let mut index = Self::default();

        for (tech_id, parsed_tech_rule) in &rule_library.core_tech_map {
            index
                .tech_info_map
                .insert(tech_id.clone(), parsed_tech_rule.basic.clone());

            for (scope, match_rule_set) in &parsed_tech_rule.match_rules {
                let scoped_rules =
                    Self::build_scoped_indexed_rules(tech_id.clone(), match_rule_set, scope)?;
                index
                    .rules
                    .entry(scope.clone())
                    .or_default()
                    .extend(scoped_rules);
            }
        }

        Ok(index)
    }

    fn build_scoped_indexed_rules(
        tech_id: String,
        match_rule_set: &MatchRuleSet,
        scope: &MatchScope,
    ) -> RswResult<Vec<ScopedIndexedRule>> {
        let mut scoped_rules = Vec::new();

        match scope {
            MatchScope::Header | MatchScope::Cookie | MatchScope::Meta | MatchScope::Js => {
                for keyed_pattern in &match_rule_set.keyed_patterns {
                    let common = CommonIndexedRule {
                        tech: tech_id.clone(),
                        match_type: keyed_pattern.pattern.match_type.clone(),
                        pattern: keyed_pattern.pattern.clone(),
                        condition: match_rule_set.condition.clone(),
                    };
                    scoped_rules.push(ScopedIndexedRule::KV {
                        common,
                        key: keyed_pattern.key.clone(),
                    });
                }
            }
            MatchScope::Url | MatchScope::Html | MatchScope::Script | MatchScope::ScriptSrc => {
                for pattern in &match_rule_set.list_patterns {
                    let common = CommonIndexedRule {
                        tech: tech_id.clone(),
                        match_type: pattern.match_type.clone(),
                        pattern: pattern.clone(),
                        condition: match_rule_set.condition.clone(),
                    };
                    scoped_rules.push(ScopedIndexedRule::Content(common));
                }
            }
        }

        Ok(scoped_rules)
    }
}

/// 规则索引构建器
pub struct RuleIndexer;

impl RuleIndexer {
    /// 构建编译后的规则库（仅结构化，不编译正则）
    pub fn build_compiled_library(index: &RuleLibraryIndex) -> RswResult<CompiledRuleLibrary> {
        let mut tech_rule_builder = TechRuleBuilder::new(&index.tech_info_map);
        for (scope, scoped_rules) in &index.rules {
            for scoped_rule in scoped_rules {
                tech_rule_builder.add_scoped_rule(scope, scoped_rule);
            }
        }

        let mut compiled_tech = FxHashMap::default();
        let mut compiled_meta = FxHashMap::default();

        for (tech_name, built_rule) in tech_rule_builder.into_iter() {
            let implies = built_rule.tech_info.implies.clone().unwrap_or_default();

            let url_patterns =
                Self::compile_content_patterns(&built_rule.url_rules, PruneScope::Url);
            let html_patterns =
                Self::compile_content_patterns(&built_rule.html_rules, PruneScope::Html);
            let script_patterns =
                Self::compile_content_patterns(&built_rule.script_rules, PruneScope::Script);
            let meta_patterns =
                Self::compile_keyed_patterns(&built_rule.meta_rules, PruneScope::Meta);
            let header_patterns =
                Self::compile_keyed_patterns(&built_rule.header_rules, PruneScope::Header);
            let cookie_patterns =
                Self::compile_keyed_patterns(&built_rule.cookie_rules, PruneScope::Cookie);

            let compiled_tech_rule = CompiledTechRule {
                name: tech_name.clone(),
                url_patterns: url_patterns,
                html_patterns: html_patterns,
                script_patterns: script_patterns,
                meta_patterns: meta_patterns,
                header_patterns: header_patterns,
                cookie_patterns: cookie_patterns,
                category_ids: built_rule.tech_info.category_ids.clone(),
                implies,
            };

            compiled_tech.insert(tech_name.clone(), compiled_tech_rule);
            // 元信息 → 存入 compiled_meta
            compiled_meta.insert(tech_name.clone(), built_rule.tech_info);
        }

        // 构建「最小证据 → 技术名称」
        let (evidence_index, no_evidence_index) = Self::build_evidence_indexes(&compiled_tech);

        Ok(CompiledRuleLibrary {
            tech_patterns: compiled_tech,
            category_map: FxHashMap::default(),
            tech_meta: compiled_meta,
            evidence_index,
            no_evidence_index,
        })
    }

    fn build_evidence_indexes(
        compiled_tech: &FxHashMap<String, CompiledTechRule>,
    ) -> (FxHashMap<String, FxHashMap<PruneScope, FxHashSet<String>>>, FxHashMap<PruneScope, FxHashSet<String>>) {
        // 带维度的最小证据索引：关键词 → 维度 → 技术名集合
        let mut evidence_index = FxHashMap::default();
        // 带维度的无证据索引：维度 → 技术名集合
        let mut no_evidence_index = FxHashMap::default();

        for (tech_name, tech_rule) in compiled_tech {
            // 1. 填充【带维度】的最小证据反向索引
            // 内容型规则 - Url维度
            Self::fill_evidence_index_with_scope(
                tech_name,
                tech_rule.url_patterns.as_ref(),
                PruneScope::Url,
                &mut evidence_index,
            );
            // 内容型规则 - Html维度
            Self::fill_evidence_index_with_scope(
                tech_name,
                tech_rule.html_patterns.as_ref(),
                PruneScope::Html,
                &mut evidence_index,
            );
            // 内容型规则 - Script维度
            Self::fill_evidence_index_with_scope(
                tech_name,
                tech_rule.script_patterns.as_ref(),
                PruneScope::Script,
                &mut evidence_index,
            );

            // 键值型规则 - Meta维度
            Self::fill_evidence_index_for_keyed_with_scope(
                tech_name,
                tech_rule.meta_patterns.as_ref(),
                PruneScope::Meta,
                &mut evidence_index,
            );
            // 键值型规则 - Header维度
            Self::fill_evidence_index_for_keyed_with_scope(
                tech_name,
                tech_rule.header_patterns.as_ref(),
                PruneScope::Header,
                &mut evidence_index,
            );
            // 键值型规则 - Cookie维度
            Self::fill_evidence_index_for_keyed_with_scope(
                tech_name,
                tech_rule.cookie_patterns.as_ref(),
                PruneScope::Cookie,
                &mut evidence_index,
            );

            // 2. 填充【带维度】的无证据反向索引
            Self::fill_no_evidence_index_with_scope(tech_name, tech_rule, &mut no_evidence_index);
        }

        (evidence_index, no_evidence_index)
    }

    // 带维度的内容型最小证据填充
    fn fill_evidence_index_with_scope(
        tech_name: &String,
        patterns: Option<&Vec<CompiledPattern>>,
        scope: PruneScope,
        evidence_map: &mut FxHashMap<String, FxHashMap<PruneScope, FxHashSet<String>>>,
    ) {
        let Some(pats) = patterns else { return };
        for pat in pats {
            // 从MatchGate中提取RequireAll的最小证据集
            if let MatchGate::RequireAll(set) = &pat.exec.match_gate {
                for evidence in set {
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

    // 带维度的键值型最小证据填充
    fn fill_evidence_index_for_keyed_with_scope(
        tech_name: &String,
        keyed_patterns: Option<&FxHashMap<String, Vec<CompiledPattern>>>,
        scope: PruneScope,
        evidence_map: &mut FxHashMap<String, FxHashMap<PruneScope, FxHashSet<String>>>,
    ) {
        let Some(keyed_pats) = keyed_patterns else {
            return;
        };
        for (_key, pats) in keyed_pats {
            for pat in pats {
                if let MatchGate::RequireAll(set) = &pat.exec.match_gate {
                    for evidence in set {
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

    // 带维度的【无证据】技术填充
    fn fill_no_evidence_index_with_scope(
        tech_name: &String,
        rule: &CompiledTechRule,
        no_evidence_map: &mut FxHashMap<PruneScope, FxHashSet<String>>,
    ) {
        // 判断是否为无证据规则：MatchGate 不是 RequireAll 即为无证据
        let is_no_evidence =
            |cp: &CompiledPattern| !matches!(&cp.exec.match_gate, MatchGate::RequireAll(_));

        // 检查Url维度
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
        // 检查Html维度
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
        // 检查Script维度
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
        // 检查Meta维度
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
        // 检查Header维度
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
        // 检查Cookie维度
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

    // 编译内容型规则，返回MatcherSpec的纯静态列表
    fn compile_content_patterns(
        rules: &[CommonIndexedRule],
        scope: PruneScope,
    ) -> Option<Vec<CompiledPattern>> {
        let mut pats = Vec::new();
        for r in rules {
            let matcher = Matcher::from_match_type_lazy(&r.match_type, &r.pattern);
            let matcher_spec = matcher.to_spec();
            let prune_strategy = Self::get_prune_strategy(&matcher);
            let min_evidence = Self::extract_min_evidence_tokens(&matcher);
            let structural_prereq = StructuralPrereq::from_matcher(&matcher);
            // 编译期折叠为统一的MatchGate
            let match_gate = fold_to_match_gate(prune_strategy, min_evidence, structural_prereq);

            // 1. 构建纯净的执行核心单元
            let exec = ExecutablePattern {
                matcher: matcher_spec,
                match_gate,
                confidence: 100,
                version_template: r.pattern.version_template.clone(),
            };

            // 2. 构建调度路由单元
            pats.push(CompiledPattern {
                scope,
                index_key: String::new(),
                exec,
            });
        }
        if pats.is_empty() {
            None
        } else {
            Some(pats)
        }
    }

    // 编译键值对型规则，返回MatcherSpec的纯静态哈希表
    fn compile_keyed_patterns(
        rules: &FxHashMap<String, Vec<CommonIndexedRule>>,
        scope: PruneScope,
    ) -> Option<FxHashMap<String, Vec<CompiledPattern>>> {
        let mut pats = FxHashMap::default();
        for (k, rs) in rules {
            let mut rule_pats = Vec::new();
            for r in rs {
                let matcher = Matcher::from_match_type_lazy(&r.match_type, &r.pattern);
                let matcher_spec = matcher.to_spec();
                let prune_strategy = Self::get_prune_strategy(&matcher);
                let min_evidence = Self::extract_min_evidence_tokens(&matcher);
                let structural_prereq = StructuralPrereq::from_matcher(&matcher);
                let match_gate =
                    fold_to_match_gate(prune_strategy, min_evidence, structural_prereq);

                let exec = ExecutablePattern {
                    matcher: matcher_spec,
                    match_gate,
                    confidence: 100,
                    version_template: r.pattern.version_template.clone(),
                };

                rule_pats.push(CompiledPattern {
                    scope,
                    index_key: k.clone(),
                    exec,
                });
            }
            if !rule_pats.is_empty() {
                pats.insert(k.to_lowercase(), rule_pats);
            }
        }
        if pats.is_empty() {
            None
        } else {
            Some(pats)
        }
    }

    // 剪枝策略分析
    #[inline(always)]
    fn get_prune_strategy(matcher: &Matcher) -> PruneStrategy {
        match matcher {
            // StartsWith → 前缀锚定剪枝，最优策略
            Matcher::StartsWith(s) => PruneStrategy::AnchorPrefix(s.to_string()),
            // Contains → 字面量匹配剪枝，精准高效
            Matcher::Contains(s) => PruneStrategy::Literal(s.to_string()),
            // 正则 → 调用工具层的剪枝策略分析
            Matcher::LazyRegex { pattern, .. } => {
                crate::utils::prune_analyzer::analyze_prune_strategy(pattern.as_str())
            }
            // Exists → 无剪枝策略
            Matcher::Exists => PruneStrategy::None,
        }
    }

    // 最小证据token提取
    #[inline(always)]
    fn extract_min_evidence_tokens(matcher: &Matcher) -> FxHashSet<String> {
        match matcher {
            Matcher::Contains(s) | Matcher::StartsWith(s) => {
                // 显式解引用Arc<String>为&str，小写转换
                let literal = safe_lowercase(s.as_str());
                if literal.len() > 1 {
                    regex_filter::extract_evidence::split_to_atomic_tokens(&literal)
                } else {
                    FxHashSet::default()
                }
            }
            // 正则类型：调用工具层的纯通用提取逻辑
            Matcher::LazyRegex { pattern, .. } => {
                regex_filter::extract_evidence::extract_min_evidence_tokens(pattern.as_str())
            }
            // Exists：无证据，返回空集
            Matcher::Exists => FxHashSet::default(),
        }
    }
}

/// 技术规则构建器
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

    fn add_scoped_rule(&mut self, scope: &MatchScope, scoped_rule: &ScopedIndexedRule) {
        let common_rule = scoped_rule.common();
        let tech_name = &common_rule.tech;

        let tech_rule = self
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
            (MatchScope::Url, _) => tech_rule.url_rules.push(common_rule.clone()),
            (MatchScope::Html, _) => tech_rule.html_rules.push(common_rule.clone()),
            (MatchScope::Script | MatchScope::ScriptSrc, _) => {
                tech_rule.script_rules.push(common_rule.clone())
            }
            (MatchScope::Meta, ScopedIndexedRule::KV { key, .. }) => {
                tech_rule
                    .meta_rules
                    .entry(key.clone())
                    .or_default()
                    .push(common_rule.clone());
            }
            (MatchScope::Header, ScopedIndexedRule::KV { key, .. }) => {
                tech_rule
                    .header_rules
                    .entry(key.clone())
                    .or_default()
                    .push(common_rule.clone());
            }
            (MatchScope::Cookie, ScopedIndexedRule::KV { key, .. }) => tech_rule
                .cookie_rules
                .entry(key.clone())
                .or_default()
                .push(common_rule.clone()),
            _ => warn!("技术[{}]的{}维度规则类型错误", tech_name, scope.to_string()),
        }
    }

    fn into_iter(self) -> impl Iterator<Item = (String, BuiltTechRule)> {
        self.tech_rules.into_iter()
    }
}

#[derive(Debug, Clone, Default)]
struct BuiltTechRule {
    tech_info: TechBasicInfo,
    url_rules: Vec<CommonIndexedRule>,
    html_rules: Vec<CommonIndexedRule>,
    script_rules: Vec<CommonIndexedRule>,
    meta_rules: FxHashMap<String, Vec<CommonIndexedRule>>,
    header_rules: FxHashMap<String, Vec<CommonIndexedRule>>,
    cookie_rules: FxHashMap<String, Vec<CommonIndexedRule>>,
}
