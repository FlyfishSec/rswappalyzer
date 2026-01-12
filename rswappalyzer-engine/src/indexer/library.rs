use std::{ops::Deref, sync::Arc};

use crate::{
    CommonIndexedRule, CoreResult, ac_manager::AcAutomatonCache, core::{MatchRuleSet, MatchScope, RuleLibrary, TechBasicInfo}, indexer::index_rules::ScopedIndexedRule, scope_pruner::PruneScope
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
    /// 规则库中所有已知的证据集token（全局唯一）
    pub known_tokens: FxHashSet<String>, 
    /// 按 scope 的派生加速索引
    pub known_tokens_by_scope: FxHashMap<PruneScope, FxHashSet<String>>,
    /// 无最小证据规则（按 scope 维度） scope -> techs
    pub no_evidence_index: FxHashMap<PruneScope, FxHashSet<String>>,
        /// literal 反向索引（literal -> scope -> techs）
    pub literal_index: FxHashMap<String, FxHashMap<PruneScope, FxHashSet<String>>>,
    /// 规则库中所有已知的 literal（全局，Vec 便于构建 AC）
    pub known_literals: Vec<String>,
    /// 按 scope 分组的 known_literals
    pub known_literals_by_scope: FxHashMap<PruneScope, FxHashSet<String>>,
    /// any 反向索引（any_literal -> scope -> techs）
    pub any_index: FxHashMap<String, FxHashMap<PruneScope, FxHashSet<String>>>,
    /// 规则库中所有已知的 any literal（全局，Vec 便于构建 AC）
    pub known_any_literals: Vec<String>,
    /// 按 scope 分组的 known_any_literals
    pub known_any_by_scope: FxHashMap<PruneScope, FxHashSet<String>>,
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


// 规则库运行时实例（包含静态规则库 + 动态 AC 自动机）
#[derive(Debug, Clone)]
pub struct RuleLibraryRuntime {
    // 静态规则库（可序列化/反序列化）
    pub compiled_lib: Arc<CompiledRuleLibrary>,
    // 动态 AC 自动机缓存（运行时构建，不序列化）
    pub ac_cache: Arc<AcAutomatonCache>,
}

impl RuleLibraryRuntime {
    /// 从静态规则库构建运行时实例（重建 AC 自动机）
    pub fn from_compiled(compiled_lib: CompiledRuleLibrary) -> CoreResult<Self> {
        // 基于 compiled_lib 中的 known_literals/known_any_literals 构建 AC 自动机
        let ac_cache = AcAutomatonCache::new(&compiled_lib)?;

        Ok(Self {
            compiled_lib: Arc::new(compiled_lib), 
            ac_cache: Arc::new(ac_cache),
        })
    }

    /// 从缓存文件加载静态规则库，再构建运行时实例
    pub fn from_cache_file(path: &str) -> CoreResult<Self> {
        // 1. 反序列化静态规则库
        let file = std::fs::File::open(path)?;
        let compiled_lib: CompiledRuleLibrary = serde_json::from_reader(file)?;
        
        // 2. 构建 AC 自动机
        let ac_cache = AcAutomatonCache::new(&compiled_lib)?;
        
        Ok(Self {
            compiled_lib: Arc::new(compiled_lib), 
            ac_cache: Arc::new(ac_cache),
        })
    }

    /// 将静态规则库保存到缓存文件
    pub fn save_cache_file(&self, path: &str) -> CoreResult<()> {
        let file = std::fs::File::create(path)?;
        serde_json::to_writer(file, &self.compiled_lib)?;
        Ok(())
    }
}

impl Deref for RuleLibraryRuntime {
    type Target = CompiledRuleLibrary;

    fn deref(&self) -> &Self::Target {
        &self.compiled_lib
    }
}