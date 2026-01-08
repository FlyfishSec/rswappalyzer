use crate::{
    CommonIndexedRule, CoreResult, core::{MatchRuleSet, MatchScope, RuleLibrary, TechBasicInfo}, indexer::index_rules::ScopedIndexedRule, scope_pruner::PruneScope
};
use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};

// 规则库索引 - 纯静态结构
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleLibraryIndex {
    pub rules: FxHashMap<MatchScope, Vec<ScopedIndexedRule>>,
    pub tech_info_map: FxHashMap<String, TechBasicInfo>,
}

// 编译后规则库
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledRuleLibrary {
    pub tech_patterns: FxHashMap<String, super::CompiledTechRule>,
    pub category_map: FxHashMap<u32, String>,
    pub tech_meta: FxHashMap<String, TechBasicInfo>,
    /// 无最小证据规则（按 scope 维度） scope -> techs
    pub evidence_index: FxHashMap<String, FxHashMap<PruneScope, FxHashSet<String>>>,
    pub no_evidence_index: FxHashMap<PruneScope, FxHashSet<String>>,
}

// RuleLibraryIndex
impl RuleLibraryIndex {
    pub fn from_rule_library(rule_library: &RuleLibrary) -> CoreResult<Self> {
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
    ) -> CoreResult<Vec<ScopedIndexedRule>> {
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