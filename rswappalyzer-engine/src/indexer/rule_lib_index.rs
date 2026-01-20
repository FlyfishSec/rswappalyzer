use std::{ops::Deref, sync::Arc};

use crate::{
    CommonIndexedRule, CompiledRuleLibrary, CoreResult, cache::AcAutomatonCache, compiled::CompiledBundle, core::{MatchRuleSet, MatchScope, RuleLibrary, TechBasicInfo}, indexer::index_rules::ScopedIndexedRule
};
use rustc_hash::{FxHashMap};
use serde::{Deserialize, Serialize};

// 规则库索引 - 纯静态结构
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleLibraryIndex {
    pub rules: FxHashMap<MatchScope, Vec<ScopedIndexedRule>>,
    pub tech_info_map: FxHashMap<String, TechBasicInfo>,
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
    //  CompiledBundle（包含映射池+规则库）
    pub compiled_bundle: Arc<CompiledBundle>,
    // 动态 AC 自动机缓存（运行时构建，不序列化）
    pub ac_cache: Arc<AcAutomatonCache>,
}

impl RuleLibraryRuntime {
    /// 从 CompiledBundle 构建
    pub fn from_compiled_bundle(compiled_bundle: CompiledBundle) -> CoreResult<Self> {
        // 适配 AC 构建：传入 CompiledBundle（内部从 ID 映射为字符串）
        let ac_cache = AcAutomatonCache::new(&compiled_bundle)?;

        Ok(Self {
            compiled_bundle: Arc::new(compiled_bundle),
            ac_cache: Arc::new(ac_cache),
        })
    }

    /// 从缓存文件加载 CompiledBundle
    pub fn from_cache_file(path: &str) -> CoreResult<Self> {
        // 1. 反序列化 CompiledBundle
        let file = std::fs::File::open(path)?;
        let compiled_bundle: CompiledBundle = serde_json::from_reader(file)?;
        
        // 2. 构建 AC 自动机
        let ac_cache = AcAutomatonCache::new(&compiled_bundle)?;
        
        Ok(Self {
            compiled_bundle: Arc::new(compiled_bundle),
            ac_cache: Arc::new(ac_cache),
        })
    }

    /// 保存 CompiledBundle 到缓存文件
    pub fn save_cache_file(&self, path: &str) -> CoreResult<()> {
        let file = std::fs::File::create(path)?;
        // 序列化 CompiledBundle（而非 CompiledRuleLibrary）
        serde_json::to_writer(file, &self.compiled_bundle)?;
        Ok(())
    }

    /// 便捷方法：获取底层的 CompiledRuleLibrary
    pub fn compiled_lib(&self) -> &CompiledRuleLibrary {
        &self.compiled_bundle.library
    }
}

impl Deref for RuleLibraryRuntime {
    type Target = CompiledRuleLibrary;

    // Deref 到 CompiledBundle 中的 library
    fn deref(&self) -> &Self::Target {
        &self.compiled_bundle.library
    }
}