use log::{debug, warn};

use crate::RuleLibrary;
use crate::error::{RswResult};
use crate::rule::cleaner::RuleCleaner;
use crate::rule::core::{TechBasicInfo};
use crate::rule::cache::RuleCacheManager;
use crate::RuleConfig;
use crate::rule::indexer::indexed_rule::{ScopedIndexedRule, CommonIndexedRule};
use crate::rule::indexer::rule_indexer::RuleLibraryIndex;
use crate::rule::indexer::scope::MatchScope;

/// 规则处理器
#[derive(Default)]
pub struct RuleProcessor;

impl RuleProcessor {
    // Embedded模式加载规则
    pub fn load_embedded(&self) -> RswResult<RuleLibrary> {
        Ok(RuleLibrary::default())
    }

    /// 构建索引库
    pub fn build_index(&self, rule_lib: &mut RuleLibrary) -> RuleLibraryIndex {
        let mut index = RuleLibraryIndex::default();

        // 辅助函数：判断是否为 KV 型作用域（Header/Meta）
        fn is_keyed_scope(scope: &MatchScope) -> bool {
            matches!(scope, MatchScope::Header | MatchScope::Meta)
        }

        for (tech_name, tech_rule) in &rule_lib.core_tech_map {
            // 技术基础信息
            let tech_info = TechBasicInfo::from(tech_rule);
            index.tech_info_map.insert(tech_name.clone(), tech_info);

            // 遍历 match_rules 构建索引
            for (scope, rule_set) in &tech_rule.match_rules {
                if is_keyed_scope(scope) {
                    // 1. KV 型规则（Header/Meta）：构建 ScopedIndexedRule::KV 变体
                    for keyed_pat in &rule_set.keyed_patterns {
                        let common_rule = CommonIndexedRule {
                            tech: tech_name.clone(),
                            match_type: keyed_pat.pattern.match_type.clone(),
                            pattern: keyed_pat.pattern.clone(),
                            condition: rule_set.condition.clone(),
                        };

                        let scoped_rule = ScopedIndexedRule::KV {
                            common: common_rule,
                            key: keyed_pat.key.clone(),
                        };

                        index.rules.entry(scope.clone())
                            .or_default()
                            .push(scoped_rule);
                    }
                } else {
                    // 2. 列表型规则：构建 ScopedIndexedRule::Content 变体
                    for pattern in &rule_set.list_patterns {
                        let common_rule = CommonIndexedRule {
                            tech: tech_name.clone(),
                            match_type: pattern.match_type.clone(),
                            pattern: pattern.clone(),
                            condition: rule_set.condition.clone(),
                        };

                        let scoped_rule = ScopedIndexedRule::Content(common_rule);

                        index.rules.entry(scope.clone())
                            .or_default()
                            .push(scoped_rule);
                    }
                }
            }
        }

        // 调试日志
        let get_rule_count = |scope: &MatchScope| -> usize {
            index.rules.get(scope).map_or(0, |rules| rules.len())
        };

        debug!(
            "索引构建完成：URL={}, HTML={}, Script={}, ScriptSrc={}, Meta={}, Header={}",
            get_rule_count(&MatchScope::Url),
            get_rule_count(&MatchScope::Html),
            get_rule_count(&MatchScope::Script),
            get_rule_count(&MatchScope::ScriptSrc),
            get_rule_count(&MatchScope::Meta),
            get_rule_count(&MatchScope::Header),
        );

        index
    }

    /// 清理并构建索引
    pub fn clean_and_split_rules(&self, rule_lib: &RuleLibrary) -> RswResult<RuleLibrary> {
        let cleaner = RuleCleaner::default();
        let mut cleaned_rule_lib = cleaner.clean(rule_lib)?;
        let _index = self.build_index(&mut cleaned_rule_lib);
        Ok(cleaned_rule_lib)
    }

    /// 优先从缓存加载规则
    pub async fn load_from_cache(&self, config: &RuleConfig) -> Option<RuleLibrary> {
        match RuleCacheManager::load_from_cache(config) {
            Ok(mut rule_lib) => {
                debug!("从本地缓存加载规则库成功");
                if rule_lib.core_tech_map.is_empty() {
                    self.build_index(&mut rule_lib);
                }
                Some(rule_lib)
            }
            Err(e) => {
                warn!("本地缓存加载失败：{}", e);
                None
            }
        }
    }

    /// 缓存最终规则
    pub async fn save_to_cache(&self, config: &RuleConfig, rule_lib: &RuleLibrary) {
        if let Err(e) = RuleCacheManager::save_to_cache(config, rule_lib) {
            warn!("规则库缓存到本地失败：{}", e);
        } else {
            debug!("规则库已缓存到本地");
        }
    }

    /// Script 规则统计
    pub fn debug_count_script_rules(&self, rule_lib: &RuleLibrary) {
        let mut has_script = 0;
        let mut has_script_src = 0;
        let mut script_patterns = 0;
        let mut script_src_patterns = 0;
    
        for tech_rule in rule_lib.core_tech_map.values() {
            if let Some(rule_set) = tech_rule.match_rules.get(&MatchScope::Script) {
                has_script += 1;
                script_patterns += rule_set.list_patterns.len();
            }
    
            if let Some(rule_set) = tech_rule.match_rules.get(&MatchScope::ScriptSrc) {
                has_script_src += 1;
                script_src_patterns += rule_set.list_patterns.len();
            }
        }
    
        debug!("===== Script 规则统计 =====");
        debug!("  技术规则总数：{}", rule_lib.core_tech_map.len());
        debug!("  有 Script 的技术数：{}", has_script);
        debug!("  有 ScriptSrc 的技术数：{}", has_script_src);
        debug!("  Script 规则数：{}", script_patterns);
        debug!("  ScriptSrc 规则数：{}", script_src_patterns);
        debug!("  脚本规则总数：{}", script_patterns + script_src_patterns);
    }
}