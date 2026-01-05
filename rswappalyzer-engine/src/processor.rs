use crate::{
    cleaner::RuleCleaner,
    core::{MatchScope, RuleLibrary, TechBasicInfo},
    indexer::{CommonIndexedRule, RuleLibraryIndex, ScopedIndexedRule},
};
use std::error::Error;

/// 规则处理器，核心职责：清洗规则 + 构建索引 + 统计调试
#[derive(Default)]
pub struct RuleProcessor;

impl RuleProcessor {
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

        println!(
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
    pub fn clean_and_split_rules(&self, rule_lib: &RuleLibrary) -> Result<RuleLibrary, Box<dyn Error>> {
        let cleaner = RuleCleaner::default();
        let cleaned_rule_lib = cleaner.clean(rule_lib)?;
        self.build_index(&cleaned_rule_lib);
        Ok(cleaned_rule_lib)
    }
}