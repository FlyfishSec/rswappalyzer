use crate::{
    CoreResult, cleaner::RuleCleaner, core::{MatchScope, RuleLibrary, TechBasicInfo}, indexer::{CommonIndexedRule, RuleLibraryIndex, ScopedIndexedRule}
};

/// 规则处理器，核心职责：清洗规则 + 构建索引 + 统计调试
#[derive(Default)]
pub struct RuleProcessor;

impl RuleProcessor {
    // Embedded模式加载规则
    pub fn load_embedded(&self) -> CoreResult<RuleLibrary> {
        Ok(RuleLibrary::default())
    }

    /// 构建索引库
    pub fn build_index(&self, rule_lib: &RuleLibrary) -> RuleLibraryIndex {
        let mut index = RuleLibraryIndex::default();

        // 辅助函数：判断是否为 KV 型作用域（Header/Meta/Cookie）
        fn is_keyed_scope(scope: &MatchScope) -> bool {
            matches!(scope, MatchScope::Header | MatchScope::Meta | MatchScope::Cookie)
        }

        for (tech_name, tech_rule) in &rule_lib.core_tech_map {
            // 写入技术基础信息
            let tech_info = TechBasicInfo::from(tech_rule);
            index.tech_info_map.insert(tech_name.clone(), tech_info);

            // 遍历 match_rules 构建索引
            for (scope, rule_set) in &tech_rule.match_rules {
                if is_keyed_scope(scope) {
                    // KV 型规则：构建 ScopedIndexedRule::KV 变体
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

                        index.rules.entry(scope.clone()).or_default().push(scoped_rule);
                    }
                } else {
                    // 列表型规则：构建 ScopedIndexedRule::Content 变体
                    for pattern in &rule_set.list_patterns {
                        let common_rule = CommonIndexedRule {
                            tech: tech_name.clone(),
                            match_type: pattern.match_type.clone(),
                            pattern: pattern.clone(),
                            condition: rule_set.condition.clone(),
                        };

                        let scoped_rule = ScopedIndexedRule::Content(common_rule);

                        index.rules.entry(scope.clone()).or_default().push(scoped_rule);
                    }
                }
            }
        }

        // 调试日志
        let get_rule_count = |scope: &MatchScope| -> usize {
            index.rules.get(scope).map_or(0, |rules| rules.len())
        };

        log::debug!(
            "索引构建完成：URL={}, HTML={}, Script={}, ScriptSrc={}, Meta={}, Header={}, Cookie={}, Js={}",
            get_rule_count(&MatchScope::Url),
            get_rule_count(&MatchScope::Html),
            get_rule_count(&MatchScope::Script),
            get_rule_count(&MatchScope::ScriptSrc),
            get_rule_count(&MatchScope::Meta),
            get_rule_count(&MatchScope::Header),
            get_rule_count(&MatchScope::Cookie),
            get_rule_count(&MatchScope::Js),
        );

        index
    }

    /// 清理并构建索引
    pub fn clean_and_split_rules(&self, rule_lib: &RuleLibrary) -> CoreResult<RuleLibrary> {
        let cleaner = RuleCleaner::default();
        let cleaned_rule_lib = cleaner.clean(rule_lib)?;
        self.build_index(&cleaned_rule_lib);
        Ok(cleaned_rule_lib)
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
    
        log::debug!("===== Script 规则统计 =====");
        log::debug!("  技术规则总数：{}", rule_lib.core_tech_map.len());
        log::debug!("  有 Script 的技术数：{}", has_script);
        log::debug!("  有 ScriptSrc 的技术数：{}", has_script_src);
        log::debug!("  Script 规则数：{}", script_patterns);
        log::debug!("  ScriptSrc 规则数：{}", script_src_patterns);
        log::debug!("  脚本规则总数：{}", script_patterns + script_src_patterns);
    }

}