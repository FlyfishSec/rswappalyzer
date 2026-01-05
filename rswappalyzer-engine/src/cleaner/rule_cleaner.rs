//! 负责整体清理流程的串联
use super::clean_stats::CleanStats;
use super::pattern_processor::PatternProcessor;
use crate::RuleLibrary;
use crate::core::{
    CategoryRule, KeyedPattern, MatchRuleSet, MatchScope, ParsedTechRule, TechBasicInfo,
};
use crate::indexer::RawMatchSet;
//use std::collections::HashMap;
use rustc_hash::FxHashMap as HashMap;
use std::error::Error;

/// 规则清理器
#[derive(Default)]
pub struct RuleCleaner {
    pattern_processor: PatternProcessor,
}

impl RuleCleaner {
    /// 从原始规则数据清理并产出统一的 match_rules
    pub fn clean_from_raw(
        &self,
        _tech_name: &str,
        raw_rules: &RawMatchSet,
    ) -> Result<HashMap<MatchScope, MatchRuleSet>, Box<dyn Error>> {
        let mut match_rules: HashMap<MatchScope, MatchRuleSet> = HashMap::default();

        // 1. 处理 列表型规则（Url/Html/Script/ScriptSrc）→ 赋值给 list_patterns
        if let Some(url_patterns) = &raw_rules.url_patterns {
            if !url_patterns.0.is_empty() {
                match_rules.insert(
                    MatchScope::Url,
                    MatchRuleSet {
                        condition: Default::default(),         // 默认 Or 条件
                        list_patterns: url_patterns.0.clone(), // 替换：patterns → list_patterns
                        keyed_patterns: Vec::new(),            // KV型字段置空
                    },
                );
            }
        }

        if let Some(html_patterns) = &raw_rules.html_patterns {
            if !html_patterns.0.is_empty() {
                match_rules.insert(
                    MatchScope::Html,
                    MatchRuleSet {
                        condition: Default::default(),
                        list_patterns: html_patterns.0.clone(), // 替换：patterns → list_patterns
                        keyed_patterns: Vec::new(),
                    },
                );
            }
        }

        if let Some(script_patterns) = &raw_rules.script_patterns {
            if !script_patterns.0.is_empty() {
                match_rules.insert(
                    MatchScope::Script,
                    MatchRuleSet {
                        condition: Default::default(),
                        list_patterns: script_patterns.0.clone(), // 替换：patterns → list_patterns
                        keyed_patterns: Vec::new(),
                    },
                );
            }
        }

        if let Some(script_src_patterns) = &raw_rules.script_src_patterns {
            if !script_src_patterns.0.is_empty() {
                match_rules.insert(
                    MatchScope::ScriptSrc,
                    MatchRuleSet {
                        condition: Default::default(),
                        list_patterns: script_src_patterns.0.clone(), // 替换：patterns → list_patterns
                        keyed_patterns: Vec::new(),
                    },
                );
            }
        }

        // 2. 处理 KV 型规则（Meta/Header/Cookie）→ 转换为 KeyedPattern 后赋值给 keyed_patterns
        if let Some(meta_pattern_map) = &raw_rules.meta_pattern_map {
            if !meta_pattern_map.0.is_empty() {
                // 将 PatternMap 转换为 KeyedPattern 列表
                let keyed_patterns: Vec<KeyedPattern> = meta_pattern_map
                    .0
                    .clone()
                    .into_iter()
                    .flat_map(|(key, patterns)| {
                        patterns.into_iter().map(move |pattern| KeyedPattern {
                            key: key.to_lowercase(), // 键名统一小写
                            pattern,
                        })
                    })
                    .collect();

                if !keyed_patterns.is_empty() {
                    match_rules.insert(
                        MatchScope::Meta,
                        MatchRuleSet {
                            condition: Default::default(),
                            list_patterns: Vec::new(), // 列表型字段置空
                            keyed_patterns,            // 赋值 KV 型规则
                        },
                    );
                }
            }
        }

        if let Some(header_pattern_map) = &raw_rules.header_pattern_map {
            if !header_pattern_map.0.is_empty() {
                // 将 PatternMap 转换为 KeyedPattern 列表
                let keyed_patterns: Vec<KeyedPattern> = header_pattern_map
                    .0
                    .clone()
                    .into_iter()
                    .flat_map(|(key, patterns)| {
                        patterns.into_iter().map(move |pattern| KeyedPattern {
                            key: key.to_lowercase(), // HTTP 头字段统一小写
                            pattern,
                        })
                    })
                    .collect();
                if !keyed_patterns.is_empty() {
                    match_rules.insert(
                        MatchScope::Header,
                        MatchRuleSet {
                            condition: Default::default(),
                            list_patterns: Vec::new(), // 列表型字段置空
                            keyed_patterns,            // 赋值 KV 型规则
                        },
                    );
                }
            }
        }

        if let Some(cookie_pattern_map) = &raw_rules.cookie_pattern_map {
            if !cookie_pattern_map.0.is_empty() {
                // 将 PatternMap 转换为 KeyedPattern 列表
                let keyed_patterns: Vec<KeyedPattern> = cookie_pattern_map
                    .0
                    .clone()
                    .into_iter()
                    .flat_map(|(key, patterns)| {
                        patterns.into_iter().map(move |pattern| KeyedPattern {
                            key: key.to_lowercase(),
                            pattern,
                        })
                    })
                    .collect();
                if !keyed_patterns.is_empty() {
                    match_rules.insert(
                        MatchScope::Cookie,
                        MatchRuleSet {
                            condition: Default::default(),
                            list_patterns: Vec::new(), // 列表型字段置空
                            keyed_patterns,            // 赋值 KV 型规则
                        },
                    );
                }
            }
        }

        //debug!("技术 {} 清理完成，生成 {} 个匹配作用域规则", tech_name, match_rules.len());
        Ok(match_rules)
    }

    /// 清理并预处理原始规则库
    pub fn clean(&self, original_rule_lib: &RuleLibrary) -> Result<RuleLibrary, Box<dyn Error>> {
        let start = std::time::Instant::now();
        let mut cleaned_tech_rules = HashMap::default();
        let mut clean_stats = CleanStats::default();

        // 遍历所有技术规则
        for (tech_name, original_tech) in &original_rule_lib.core_tech_map {
            clean_stats.total_original_tech_rules += 1;

            //eprintln!("原始header {:?}, 规则 {:?}",tech_name.clone(), original_tech.clone());

            // 1. 从原始规则提取并处理所有模式，生成 RawMatchSet
            let (
                url_patterns,
                html_patterns,
                script_patterns,
                script_src_patterns,
                meta_pattern_map,
                header_pattern_map,
                cookie_pattern_map,
            ) = self
                .pattern_processor
                .process_tech_rule_patterns(original_tech, &mut clean_stats)?;

            //eprintln!("pattern_processor 后的 header_pattern_map {:?}", header_pattern_map.clone());

            let raw_match_set = RawMatchSet {
                url_patterns,
                html_patterns,
                script_patterns,
                script_src_patterns,
                meta_pattern_map,
                header_pattern_map,
                cookie_pattern_map,
            };

            // 记录原始维度是否存在规则
            let has_any_supported_dimension = raw_match_set
                .url_patterns
                .as_ref()
                .map_or(false, |p| !p.0.is_empty())
                || raw_match_set
                    .html_patterns
                    .as_ref()
                    .map_or(false, |p| !p.0.is_empty())
                || raw_match_set
                    .script_patterns
                    .as_ref()
                    .map_or(false, |p| !p.0.is_empty())
                || raw_match_set
                    .script_src_patterns
                    .as_ref()
                    .map_or(false, |p| !p.0.is_empty())
                || raw_match_set
                    .meta_pattern_map
                    .as_ref()
                    .map_or(false, |m| !m.0.is_empty())
                || raw_match_set
                    .header_pattern_map
                    .as_ref()
                    .map_or(false, |m| !m.0.is_empty())
                || raw_match_set
                    .cookie_pattern_map
                    .as_ref()
                    .map_or(false, |m| !m.0.is_empty());

            // 2. 调用核心清理方法，生成统一的 match_rules
            let match_rules = self.clean_from_raw(&tech_name.to_string(), &raw_match_set)?;

            // 判断是否有有效模式（match_rules 非空即有有效规则）
            if match_rules.is_empty() && has_any_supported_dimension {
                clean_stats.discarded_tech_rules += 1;
                println!(
                    "[CLEAN DROP] {} | 原始维度: url={} html={} script={} script_src={} meta={} header={} cookie={}",
                    tech_name,
                    raw_match_set
                        .url_patterns
                        .as_ref()
                        .map_or(false, |p| !p.0.is_empty()),
                    raw_match_set
                        .html_patterns
                        .as_ref()
                        .map_or(false, |p| !p.0.is_empty()),
                    raw_match_set
                        .script_patterns
                        .as_ref()
                        .map_or(false, |p| !p.0.is_empty()),
                    raw_match_set
                        .script_src_patterns
                        .as_ref()
                        .map_or(false, |p| !p.0.is_empty()),
                    raw_match_set
                        .meta_pattern_map
                        .as_ref()
                        .map_or(false, |m| !m.0.is_empty()),
                    raw_match_set
                        .header_pattern_map
                        .as_ref()
                        .map_or(false, |m| !m.0.is_empty()),
                    raw_match_set
                        .cookie_pattern_map
                        .as_ref()
                        .map_or(false, |m| !m.0.is_empty()),
                );

                continue;
            }

            // 3. 构建技术基础信息
            let basic_info = TechBasicInfo {
                tech_name: Some(tech_name.to_string()),
                category_ids: original_tech.basic.category_ids.clone(),
                implies: original_tech.basic.implies.clone(),

                #[cfg(feature = "full-meta")]
                description: original_tech.basic.description.clone(),
                #[cfg(feature = "full-meta")]
                website: original_tech.basic.website.clone(),
                #[cfg(feature = "full-meta")]
                icon: original_tech.basic.icon.clone(),
                #[cfg(feature = "full-meta")]
                cpe: original_tech.basic.cpe.clone(),
                #[cfg(feature = "full-meta")]
                saas: original_tech.basic.saas,
                #[cfg(feature = "full-meta")]
                pricing: original_tech.basic.pricing.clone(),
            };

            // 4. 构建新的 ParsedTechRule（仅包含 basic 和 match_rules）
            let cleaned_tech_rule = ParsedTechRule {
                basic: basic_info,
                match_rules,
            };

            cleaned_tech_rules.insert(tech_name.to_string(), cleaned_tech_rule);
            clean_stats.kept_tech_rules += 1;
        }

        let cleaned_category_rules: HashMap<u32, CategoryRule> = original_rule_lib
            .category_rules
            .iter()
            .map(|(id, cat)| {
                (
                    *id,
                    CategoryRule {
                        id: *id,
                        name: cat.name.clone(),
                        priority: cat.priority,
                    },
                )
            })
            .collect();

        // 更新并输出统计信息
        clean_stats.update_fixed_stats();
        clean_stats.print_stats(start.elapsed());

        Ok(RuleLibrary {
            core_tech_map: cleaned_tech_rules,
            category_rules: cleaned_category_rules,
        })
    }
}
