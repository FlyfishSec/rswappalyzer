use super::super::core::RuleLibrary;
use crate::RuleConfig;
use crate::error::RswResult;
use crate::rule::core::{CachedTechRule, ParsedTechRule};
use crate::rule::indexer::scope::MatchRuleSet;
use std::collections::HashMap;
use std::fs;

/// 规则缓存管理器
pub struct RuleCacheManager;

impl RuleCacheManager {
    // 同步加载缓存
    pub fn load_from_cache(config: &RuleConfig) -> RswResult<RuleLibrary> {
        let cache_data: Vec<u8> = fs::read(&config.options.cache_path)?;
        let cached_rules: Vec<CachedTechRule> = serde_json::from_slice(&cache_data)?;
        Self::convert_cached_rules(cached_rules)
    }

    // 同步保存缓存
    pub fn save_to_cache(config: &RuleConfig, rule_lib: &RuleLibrary) -> RswResult<()> {
        let cache_data = Self::build_cached_rules(rule_lib)?;
        fs::write(&config.options.cache_path, cache_data)?;
        Ok(())
    }

    // 公共逻辑：缓存规则转换
    fn convert_cached_rules(cached_rules: Vec<CachedTechRule>) -> RswResult<RuleLibrary> {
        let mut core_tech_map = HashMap::with_capacity(cached_rules.len());
        for cached in cached_rules {
            let tech_name = cached.basic.tech_name.clone().expect("缺失tech_name");
            let mut match_rules = HashMap::with_capacity(cached.rules.len());
            for (scope, cached_scope_rule) in cached.rules {
                match_rules.insert(scope.clone(), MatchRuleSet::from_cached(&scope, cached_scope_rule));
            }
            core_tech_map.insert(tech_name, ParsedTechRule { basic: cached.basic, match_rules });
        }
        Ok(RuleLibrary { core_tech_map, category_rules: HashMap::new() })
    }

    // 公共逻辑：构建缓存规则
    fn build_cached_rules(rule_lib: &RuleLibrary) -> RswResult<Vec<u8>> {
        let mut cached_rules = Vec::with_capacity(rule_lib.core_tech_map.len());
        for (_, parsed) in &rule_lib.core_tech_map {
            let mut rules = HashMap::with_capacity(parsed.match_rules.len());
            for (scope, rule_set) in &parsed.match_rules {
                rules.insert(scope.clone(), rule_set.to_cached(scope));
            }
            cached_rules.push(CachedTechRule { basic: parsed.basic.clone(), rules });
        }
        Ok(serde_json::to_vec(&cached_rules)?)
    }
}