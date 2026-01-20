//! 规则索引器（主入口）：仅负责协调各模块，按顺序执行构建流程
//! 核心：不处理具体的编译/ID转换逻辑，只做调度

use crate::{
    builder::{
        id_filler::IdFiller, no_evidence_index::NoEvidenceIndexBuilder,
        pattern_compiler::PatternCompiler,
    },
    compiled::{CompiledBundle, LiteralInterner, TechInterner},
    core::{MatchScope, TechBasicInfo},
    indexer::builder::{
        any_index::AnyIndexBuilder, contains_index::ContainsIndexBuilder,
        literal_index::LiteralIndexBuilder,
    },
    CommonIndexedRule, CompiledRuleLibrary, CompiledTechRule, CoreResult, RuleLibraryIndex, Scope,
    ScopedIndexedRule,
};
use rustc_hash::FxHashMap;

/// 技术规则构建器（临时存储）
#[derive(Debug, Clone, Default)]
struct BuiltTechRule {
    tech_info: TechBasicInfo,
    url_rules: Vec<CommonIndexedRule>,
    html_rules: Vec<CommonIndexedRule>,
    script_rules: Vec<CommonIndexedRule>,
    meta_rules: FxHashMap<String, Vec<CommonIndexedRule>>,
    header_rules: FxHashMap<String, Vec<CommonIndexedRule>>,
    cookie_rules: FxHashMap<String, Vec<CommonIndexedRule>>,
}

impl BuiltTechRule {
    // 判断是否存在有效规则
    fn has_valid_rules(&self) -> bool {
        // 检查列表型规则是否非空
        !self.url_rules.is_empty() 
        || !self.html_rules.is_empty() 
        || !self.script_rules.is_empty()
        // 检查KV型规则是否非空（只要有一个key对应的规则列表非空，就视为有有效规则）
        || self.meta_rules.values().any(|v| !v.is_empty())
        || self.header_rules.values().any(|v| !v.is_empty())
        || self.cookie_rules.values().any(|v| !v.is_empty())
    }
}

/// 技术规则构建器
struct TechRuleBuilder<'a> {
    tech_info_map: &'a FxHashMap<String, TechBasicInfo>,
    tech_rules: FxHashMap<String, BuiltTechRule>,
}

impl<'a> TechRuleBuilder<'a> {
    // fn new(tech_info_map: &'a FxHashMap<String, TechBasicInfo>) -> Self {
    //     Self {
    //         tech_info_map,
    //         tech_rules: FxHashMap::default(),
    //     }
    // }
    fn new(tech_info_map: &'a FxHashMap<String, TechBasicInfo>) -> Self {
        let mut tech_rules = FxHashMap::default();

        // 先加载所有技术项（包括纯元信息项）
        for (tech_name, tech_info) in tech_info_map {
            tech_rules.insert(
                tech_name.clone(),
                BuiltTechRule {
                    tech_info: tech_info.clone(),
                    ..BuiltTechRule::default()
                },
            );
        }

        Self {
            tech_info_map,
            tech_rules,
        }
    }

    fn add_scoped_rule(&mut self, scope: &MatchScope, scoped_rule: &ScopedIndexedRule) {
        let common = scoped_rule.common();
        let tech_name = &common.tech;

        let rule = self
            .tech_rules
            .entry(tech_name.clone())
            .or_insert_with(|| BuiltTechRule {
                tech_info: self
                    .tech_info_map
                    .get(tech_name)
                    .cloned()
                    .unwrap_or_default(),
                ..BuiltTechRule::default()
            });

        match (scope, scoped_rule) {
            (MatchScope::Url, _) => rule.url_rules.push(common.clone()),
            (MatchScope::Html, _) => rule.html_rules.push(common.clone()),
            (MatchScope::Script | MatchScope::ScriptSrc, _) => {
                rule.script_rules.push(common.clone())
            }
            (MatchScope::Meta, ScopedIndexedRule::KV { key, .. }) => rule
                .meta_rules
                .entry(key.clone())
                .or_default()
                .push(common.clone()),
            (MatchScope::Header, ScopedIndexedRule::KV { key, .. }) => rule
                .header_rules
                .entry(key.clone())
                .or_default()
                .push(common.clone()),
            (MatchScope::Cookie, ScopedIndexedRule::KV { key, .. }) => rule
                .cookie_rules
                .entry(key.clone())
                .or_default()
                .push(common.clone()),
            _ => eprintln!(
                "Tech [{}] has invalid rule type for scope {}",
                tech_name, scope
            ),
        }
    }

    fn into_iter(self) -> impl Iterator<Item = (String, BuiltTechRule)> {
        self.tech_rules.into_iter()
    }
}

/// 规则索引器（主结构体）：仅做调度，不处理具体逻辑
#[derive(Debug, Clone, Default)]
pub struct RuleIndexer;

impl RuleIndexer {
    /// 使用默认分类文件构建编译规则库
    pub fn build_compiled_library_with_default_category(
        index: &RuleLibraryIndex,
    ) -> CoreResult<CompiledBundle> {
        Self::build_compiled_library(index, Some("data/categories_data.json"))
    }

    /// 构建编译规则库（核心流程：调度各模块按顺序执行）
    pub fn build_compiled_library(
        index: &RuleLibraryIndex,
        category_json_path: Option<&str>,
    ) -> CoreResult<CompiledBundle> {
        // 1：初始化id映射池
        let mut tech_interner = TechInterner::default();
        let mut literal_interner = LiteralInterner::default();

        // 2：收集原始规则
        let mut builder = TechRuleBuilder::new(&index.tech_info_map);
        for (scope, rules) in &index.rules {
            rules.iter().for_each(|r| builder.add_scoped_rule(scope, r));
        }

        // 3：编译为无ID的CompiledTechRule
        let mut compiled_tech = FxHashMap::default();
        let mut compiled_meta = FxHashMap::default();

        for (name, rule) in builder.into_iter() {
            let implies = rule.tech_info.implies.clone().unwrap_or_default();
            if rule.has_valid_rules() {
                compiled_tech.insert(
                name.clone(),
                CompiledTechRule {
                    name: name.clone(),
                    url_patterns: PatternCompiler::compile_content_patterns(
                        &rule.url_rules,
                        Scope::Url,
                        &mut literal_interner,
                    ),
                    html_patterns: PatternCompiler::compile_content_patterns(
                        &rule.html_rules,
                        Scope::Html,
                        &mut literal_interner,
                    ),
                    script_patterns: PatternCompiler::compile_content_patterns(
                        &rule.script_rules,
                        Scope::Script,
                        &mut literal_interner,
                    ),
                    meta_patterns: PatternCompiler::compile_keyed_patterns(
                        &rule.meta_rules,
                        Scope::Meta,
                        &mut literal_interner,
                    ),
                    header_patterns: PatternCompiler::compile_keyed_patterns(
                        &rule.header_rules,
                        Scope::Header,
                        &mut literal_interner,
                    ),
                    cookie_patterns: PatternCompiler::compile_keyed_patterns(
                        &rule.cookie_rules,
                        Scope::Cookie,
                        &mut literal_interner,
                    ),
                    category_ids: rule.tech_info.category_ids.clone(),
                    implies,
                },
            );
            }

            // 无论是否有有效规则，都保留元信息
            compiled_meta.insert(name, rule.tech_info);
        }

        // 4：加载分类映射
        let category_map = match category_json_path {
            Some(path) => Self::load_category_map(path),
            None => FxHashMap::default(),
        };

        // 5：注册技术名称到TechInterner
        for tech_name in compiled_tech.keys() {
            tech_interner.get_or_insert(tech_name);
        }

        // 6：构建各索引（填充Interner）
        //let token_index = TokenIndexBuilder::build(&compiled_tech, &mut token_interner, &mut tech_interner);
        let literal_index =
            LiteralIndexBuilder::build(&compiled_tech, &mut literal_interner, &mut tech_interner);
        let contains_index =
            ContainsIndexBuilder::build(&compiled_tech, &mut literal_interner, &mut tech_interner);
        let any_index =
            AnyIndexBuilder::build(&compiled_tech, &mut literal_interner, &mut tech_interner);
        let no_evidence_index = NoEvidenceIndexBuilder::build(&compiled_tech, &mut tech_interner);

        // 7：补全所有ID字段
        let compiled_tech = IdFiller::fill_all_tech_ids(compiled_tech, &literal_interner);

        // 8：组装最终结果
        let library = CompiledRuleLibrary {
            tech_patterns: compiled_tech,
            category_map,
            tech_meta: compiled_meta,
            literal_index: literal_index.literal_index,
            known_literals: literal_index.known_literals,
            known_literals_by_scope: literal_index.known_literals_by_scope,
            any_index: any_index.any_index,
            known_any_literals: any_index.known_any_literals,
            known_any_by_scope: any_index.known_any_by_scope,
            contains_index: contains_index.contains_index,
            known_contains: contains_index.known_contains,
            known_contains_by_scope: contains_index.known_contains_by_scope,
            no_evidence_index: no_evidence_index.no_evidence_index,
        };

        Ok(CompiledBundle {
            library,
            tech_interner,
            literal_interner,
        })
    }

    /// 加载分类映射
    pub fn load_category_map(json_path: &str) -> FxHashMap<u32, String> {
        let json_content = match std::fs::read_to_string(json_path) {
            Ok(c) => c,
            Err(e) => {
                log::debug!(
                    "Category map file read failed, fallback to empty map | Path: {} | Error: {}",
                    json_path,
                    e
                );
                return FxHashMap::default();
            }
        };

        let category_entries: crate::core::CategoryJsonRoot =
            match serde_json::from_str(&json_content) {
                Ok(v) => v,
                Err(e) => {
                    log::debug!(
                        "Category map JSON parse failed, fallback to empty map | Error: {}",
                        e
                    );
                    return FxHashMap::default();
                }
            };

        let mut map = FxHashMap::default();
        for (category_id_str, entry) in category_entries {
            if entry.name.is_empty() {
                continue;
            }

            match category_id_str.parse::<u32>() {
                Ok(id) => map.insert(id, entry.name),
                Err(e) => {
                    log::debug!(
                        "Invalid category ID, skipped | ID: {} | Error: {}",
                        category_id_str,
                        e
                    );
                    None
                }
            };
        }

        map
    }
}
