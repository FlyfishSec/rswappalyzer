use std::{ops::Deref, sync::Arc};

use crate::{
    CommonIndexedRule, CompiledRuleLibrary, CoreResult, cache::AcAutomatonCache, compiled::CompiledBundle, core::{MatchRuleSet, MatchScope, RuleLibrary, TechBasicInfo}, indexer::index_rules::ScopedIndexedRule
};
use rustc_hash::FxHashMap;
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
    compiled_bundle: Arc<CompiledBundle>,
    // 动态 AC 自动机缓存（运行时构建，不序列化）
    ac_cache: Arc<AcAutomatonCache>,
}

impl RuleLibraryRuntime {
    /// 基础构造函数
    /// 核心：支持自定义 regex_cache，实现多实例共享缓存
    pub fn new(
        compiled_bundle: Arc<CompiledBundle>,
        ac_cache: Arc<AcAutomatonCache>,
        //regex_cache: Arc<RegexCache>,
        //regex_cache: &Arc<RegexCache>,
    ) -> Self {
        //let regex_cache = RegexCache::shared(config.regex_cache_config.clone());

        // // 记录Runtime初始化，打印关联的RegexCache ID和Arc地址
        // log::info!(
        //     "RuleLibraryRuntime created | regex_cache_id={}, regex_cache_arc_addr={:#x}",
        //     regex_cache.debug_id(),
        //     regex_cache.debug_arc_addr(),
        // );

        let runtime = Self {
            compiled_bundle: compiled_bundle.clone(),
            ac_cache,
        };

        // // 初始化时注入RegexCache到所有ExecutablePattern
        // let start_time_fp_detector = std::time::Instant::now();
        // //runtime.inject_regex_cache_to_all_patterns(regex_cache);
        // println!(
        //     "inject_regex_cache_to_all_patterns took: {:?}",
        //     start_time_fp_detector.elapsed()
        // );

        runtime
    }

    // /// 将RegexCache注入到所有ExecutablePattern中
    // fn inject_regex_cache_to_all_patterns(&self, regex_cache: &Arc<RegexCache>) {
    //     // 检查是否有需要处理的pattern
    //     if self.compiled_bundle.library.tech_patterns.is_empty() {
    //         return;
    //     }

    //     // 使用抽象的for_each_pattern方法，解耦遍历逻辑
    //     let cache = regex_cache.clone();
    //     self.compiled_bundle.library.for_each_pattern(|pattern: &ExecutablePattern| {
    //         pattern.inject_cache(cache.clone());
    //     });

    //     log::debug!("Successfully injected RegexCache to all ExecutablePattern instances");
    // }

    // fn inject_regex_cache_to_all_patterns(&self, regex_cache: &Arc<RegexCache>) {
    //     // 1. 检查 tech_patterns 是否为空，避免无效遍历
    //     if self.compiled_bundle.library.tech_patterns.is_empty() {
    //         return;
    //     }

    //     // 2. 遍历所有 CompiledTechRule（tech_patterns 是 HashMap<String, CompiledTechRule>）
    //     for (_tech_name, compiled_tech_rule) in &self.compiled_bundle.library.tech_patterns {
    //         // 3. 处理 URL 匹配模式
    //         if let Some(url_patterns) = &compiled_tech_rule.url_patterns {
    //             for pattern in url_patterns {
    //                 pattern.exec.inject_cache(regex_cache.clone());
    //             }
    //         }

    //         // 4. 处理 HTML 匹配模式
    //         if let Some(html_patterns) = &compiled_tech_rule.html_patterns {
    //             for pattern in html_patterns {
    //                 pattern.exec.inject_cache(regex_cache.clone());
    //             }
    //         }

    //         // 5. 处理 Script 匹配模式
    //         if let Some(script_patterns) = &compiled_tech_rule.script_patterns {
    //             for pattern in script_patterns {
    //                 pattern.exec.inject_cache(regex_cache.clone());
    //             }
    //         }

    //         // 6. 处理 Meta 匹配模式（HashMap<String, Vec<CompiledPattern>>）
    //         if let Some(meta_patterns) = &compiled_tech_rule.meta_patterns {
    //             for (_meta_key, patterns) in meta_patterns {
    //                 for pattern in patterns {
    //                     pattern.exec.inject_cache(regex_cache.clone());
    //                 }
    //             }
    //         }

    //         // 7. 处理 Header 匹配模式（HashMap<String, Vec<CompiledPattern>>）
    //         if let Some(header_patterns) = &compiled_tech_rule.header_patterns {
    //             for (_header_key, patterns) in header_patterns {
    //                 for pattern in patterns {
    //                     pattern.exec.inject_cache(regex_cache.clone());
    //                 }
    //             }
    //         }

    //         // 8. 处理 Cookie 匹配模式（HashMap<String, Vec<CompiledPattern>>）
    //         if let Some(cookie_patterns) = &compiled_tech_rule.cookie_patterns {
    //             for (_cookie_key, patterns) in cookie_patterns {
    //                 for pattern in patterns {
    //                     pattern.exec.inject_cache(regex_cache.clone());
    //                 }
    //             }
    //         }
    //     }

    //     log::debug!("Successfully injected RegexCache to all ExecutablePattern instances");
    // }

    // /// 从 CompiledBundle 构建
    // pub fn from_compiled_bundle(compiled_bundle: CompiledBundle) -> CoreResult<Self> {
    //     // 适配 AC 构建：传入 CompiledBundle（内部从 ID 映射为字符串）
    //     let ac_cache = AcAutomatonCache::new(&compiled_bundle)?;
    //     let regex_cache = Arc::new(RegexCache::default());

    //     Ok(Self {
    //         compiled_bundle: Arc::new(compiled_bundle),
    //         ac_cache: Arc::new(ac_cache),
    //         regex_cache,
    //     })
    // }

    // /// 从缓存文件加载 CompiledBundle
    // pub fn from_cache_file(path: &str) -> CoreResult<Self> {
    //     // 1. 反序列化 CompiledBundle
    //     let file = std::fs::File::open(path)?;
    //     let compiled_bundle: CompiledBundle = serde_json::from_reader(file)?;

    //     // 2. 构建 AC 自动机
    //     let ac_cache = AcAutomatonCache::new(&compiled_bundle)?;
    //     let regex_cache = Arc::new(RegexCache::default());

    //     Ok(Self {
    //         compiled_bundle: Arc::new(compiled_bundle),
    //         ac_cache: Arc::new(ac_cache),
    //         regex_cache,
    //     })
    // }

    /// 保存 CompiledBundle 到缓存文件
    pub fn save_cache_file(&self, path: &str) -> CoreResult<()> {
        let file = std::fs::File::create(path)?;
        // 序列化 CompiledBundle
        serde_json::to_writer(file, &self.compiled_bundle)?;
        Ok(())
    }

    /// 便捷方法：获取底层的 CompiledRuleLibrary
    pub fn get_compiled_lib(&self) -> &CompiledRuleLibrary {
        &self.compiled_bundle.library
    }

    pub fn get_compiled_bundle(&self) -> &CompiledBundle {
        &self.compiled_bundle
    }

    // pub fn get_regex_cache(&self) -> &Arc<RegexCache> {
    //     &self.regex_cache
    // }

    pub fn get_ac_cache(&self) -> &Arc<AcAutomatonCache> {
        &self.ac_cache
    }
}

impl Deref for RuleLibraryRuntime {
    type Target = CompiledRuleLibrary;

    // Deref 到 CompiledBundle 中的 library
    fn deref(&self) -> &Self::Target {
        &self.compiled_bundle.library
    }
}
