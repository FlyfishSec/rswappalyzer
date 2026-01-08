use rswappalyzer_engine::core::CachedTechRule;
use rswappalyzer_engine::{MatchRuleSet, ParsedTechRule, RuleLibrary};
use rustc_hash::FxHashMap;

use crate::{RswappalyzerError, RuleConfig, RuleOrigin};
use crate::error::RswResult;
use std::fs;
use std::path::PathBuf;

/// 规则缓存管理器
pub struct RuleCacheManager;

impl RuleCacheManager {
    // 同步加载缓存（修复 Option<PathBuf> 问题）
    pub fn load_from_cache(config: &RuleConfig) -> RswResult<RuleLibrary> {
        // 1. 先判断是否是内置规则（内置规则无缓存文件，直接返回错误）
        if let RuleOrigin::Embedded = config.origin {
            return Err(RswappalyzerError::InvalidInput(
                "内置规则不支持从缓存加载".to_string()
            ));
        }

        // 2. 获取确定的缓存文件路径（此时是 PathBuf 而非 Option）
        let cache_file: PathBuf = config.get_cache_file_path();
        
        // 3. 读取文件（此时 &cache_file 可正常实现 AsRef<Path>）
        let cache_data = fs::read(&cache_file).map_err(|e| {
            RswappalyzerError::IoError(e)
        })?;
        
        let cached_rules: Vec<CachedTechRule> = serde_json::from_slice(&cache_data).map_err(|e| {
            RswappalyzerError::JsonError(e.into())
        })?;
        
        Self::convert_cached_rules(cached_rules)
    }

    // 同步保存缓存（修复 Option<PathBuf> 和 parent() 方法问题）
    pub fn save_to_cache(config: &RuleConfig, rule_lib: &RuleLibrary) -> RswResult<()> {
        // 1. 内置规则不保存缓存
        if let RuleOrigin::Embedded = config.origin {
            return Err(RswappalyzerError::InvalidInput(
                "内置规则不支持保存到缓存".to_string()
            ));
        }

        // 2. 获取确定的缓存文件路径
        let cache_file: PathBuf = config.get_cache_file_path();
        
        // 3. 获取父目录并创建（修复 parent() 调用错误）
        if let Some(parent_dir) = cache_file.parent() {
            fs::create_dir_all(parent_dir).map_err(|e| {
                RswappalyzerError::IoError(e)
            })?;
        }

        // 4. 写入文件（此时 &cache_file 类型正确）
        let cache_data = Self::build_cached_rules(rule_lib)?;
        fs::write(&cache_file, cache_data).map_err(|e| {
            RswappalyzerError::IoError(e)
        })?;
        
        Ok(())
    }

    // 公共逻辑：缓存规则转换
    fn convert_cached_rules(cached_rules: Vec<CachedTechRule>) -> RswResult<RuleLibrary> {
        let mut core_tech_map = FxHashMap::default();
        for cached in cached_rules {
            let tech_name = cached.basic.tech_name.clone().ok_or_else(|| {
                RswappalyzerError::InvalidInput("缓存规则缺失 tech_name 字段".to_string())
            })?;
            let mut match_rules = FxHashMap::default();
            for (scope, cached_scope_rule) in cached.rules {
                match_rules.insert(scope.clone(), MatchRuleSet::from_cached(&scope, cached_scope_rule));
            }
            core_tech_map.insert(tech_name, ParsedTechRule { basic: cached.basic, match_rules });
        }
        Ok(RuleLibrary { core_tech_map, category_rules: FxHashMap::default() })
    }

    // 公共逻辑：构建缓存规则
    fn build_cached_rules(rule_lib: &RuleLibrary) -> RswResult<Vec<u8>> {
        let mut cached_rules = Vec::with_capacity(rule_lib.core_tech_map.len());
        for (_, parsed) in &rule_lib.core_tech_map {
            let mut rules = FxHashMap::default();
            for (scope, rule_set) in &parsed.match_rules {
                rules.insert(scope.clone(), rule_set.to_cached(scope));
            }
            cached_rules.push(CachedTechRule { basic: parsed.basic.clone(), rules });
        }
        serde_json::to_vec(&cached_rules).map_err(|e| RswappalyzerError::JsonError(e.into()))
    }
}