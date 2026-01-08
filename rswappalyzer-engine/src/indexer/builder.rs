use crate::{
    core::{CategoryJsonRoot, TechBasicInfo},
    indexer::{
        compiled::CompiledTechRule,
        index_rules::CommonIndexedRule,
        library::CompiledRuleLibrary,
        matcher::{fold_to_match_gate, Matcher},
        CompiledPattern, ExecutablePattern, MatchGate, RuleLibraryIndex, ScopedIndexedRule,
        StructuralPrereq,
    },
    prune_strategy::PruneStrategy,
    pruner::*,
    pruner::{min_evidence, tokenizer},
    scope_pruner::PruneScope,
    utils::safe_lower::safe_lowercase,
    CoreResult,
};
use once_cell::sync::OnceCell;
use rustc_hash::{FxHashMap, FxHashSet};

// 内部构建器：临时存储技术规则的分类数据
#[derive(Debug, Clone, Default)]
struct BuiltTechRule {
    /// 技术基础信息
    tech_info: TechBasicInfo,
    /// URL匹配规则列表
    url_rules: Vec<CommonIndexedRule>,
    /// HTML匹配规则列表
    html_rules: Vec<CommonIndexedRule>,
    /// Script匹配规则列表
    script_rules: Vec<CommonIndexedRule>,
    /// Meta匹配规则映射（Key=Meta名称）
    meta_rules: FxHashMap<String, Vec<CommonIndexedRule>>,
    /// Header匹配规则映射（Key=Header名称）
    header_rules: FxHashMap<String, Vec<CommonIndexedRule>>,
    /// Cookie匹配规则映射（Key=Cookie名称）
    cookie_rules: FxHashMap<String, Vec<CommonIndexedRule>>,
}

/// 技术规则构建器（生命周期内）
/// 职责：将索引后的规则按技术名称和作用域分类，构建临时规则结构
struct TechRuleBuilder<'a> {
    /// 技术基础信息映射（外部引用）
    tech_info_map: &'a FxHashMap<String, TechBasicInfo>,
    /// 按技术名称分组的临时规则存储
    tech_rules: FxHashMap<String, BuiltTechRule>,
}

impl<'a> TechRuleBuilder<'a> {
    /// 创建技术规则构建器实例
    /// 参数：tech_info_map - 技术基础信息映射（外部引用）
    fn new(tech_info_map: &'a FxHashMap<String, TechBasicInfo>) -> Self {
        Self {
            tech_info_map,
            tech_rules: FxHashMap::default(),
        }
    }

    /// 添加作用域规则到构建器
    /// 参数：
    /// - scope: 匹配作用域（URL/HTML/Meta等）
    /// - scoped_rule: 作用域索引规则
    fn add_scoped_rule(
        &mut self,
        scope: &crate::core::MatchScope,
        scoped_rule: &ScopedIndexedRule,
    ) {
        let common = scoped_rule.common();
        let tech_name = &common.tech;

        // 获取或创建技术规则条目
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

        // 按作用域分类存储规则
        match (scope, scoped_rule) {
            (crate::core::MatchScope::Url, _) => rule.url_rules.push(common.clone()),
            (crate::core::MatchScope::Html, _) => rule.html_rules.push(common.clone()),
            (crate::core::MatchScope::Script | crate::core::MatchScope::ScriptSrc, _) => {
                rule.script_rules.push(common.clone())
            }
            (crate::core::MatchScope::Meta, ScopedIndexedRule::KV { key, .. }) => rule
                .meta_rules
                .entry(key.clone())
                .or_default()
                .push(common.clone()),
            (crate::core::MatchScope::Header, ScopedIndexedRule::KV { key, .. }) => rule
                .header_rules
                .entry(key.clone())
                .or_default()
                .push(common.clone()),
            (crate::core::MatchScope::Cookie, ScopedIndexedRule::KV { key, .. }) => rule
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

    /// 转换为迭代器（消费构建器）
    fn into_iter(self) -> impl Iterator<Item = (String, BuiltTechRule)> {
        self.tech_rules.into_iter()
    }
}

/// 规则索引器
/// 核心职责：
/// 1. 将索引后的规则编译为可执行的CompiledRuleLibrary
/// 2. 构建证据索引和无证据索引，用于快速匹配
/// 3. 加载分类映射，完善技术分类信息
pub struct RuleIndexer;

impl RuleIndexer {
    /// 使用默认分类文件构建编译规则库
    /// 参数：index - 规则库索引
    /// 返回：编译后的规则库 | 错误
    pub fn build_compiled_library_with_default_category(
        index: &RuleLibraryIndex,
    ) -> CoreResult<CompiledRuleLibrary> {
        Self::build_compiled_library(index, Some("data/categories_data.json"))
    }

    /// 构建编译规则库（无日志）
    /// 参数：
    /// - index: 规则库索引
    /// - category_json_path: 分类JSON文件路径（可选）
    /// 返回：编译后的规则库 | 错误
    pub fn build_compiled_library(
        index: &RuleLibraryIndex,
        category_json_path: Option<&str>,
    ) -> CoreResult<CompiledRuleLibrary> {
        // 1. 构建临时技术规则
        let mut builder = TechRuleBuilder::new(&index.tech_info_map);
        for (scope, rules) in &index.rules {
            rules.iter().for_each(|r| builder.add_scoped_rule(scope, r));
        }

        // 2. 编译为CompiledTechRule
        let mut compiled_tech = FxHashMap::default();
        let mut compiled_meta = FxHashMap::default();

        for (name, rule) in builder.into_iter() {
            let implies = rule.tech_info.implies.clone().unwrap_or_default();
            compiled_tech.insert(
                name.clone(),
                CompiledTechRule {
                    name: name.clone(),
                    url_patterns: Self::compile_content_patterns(&rule.url_rules, PruneScope::Url),
                    html_patterns: Self::compile_content_patterns(
                        &rule.html_rules,
                        PruneScope::Html,
                    ),
                    script_patterns: Self::compile_content_patterns(
                        &rule.script_rules,
                        PruneScope::Script,
                    ),
                    meta_patterns: Self::compile_keyed_patterns(&rule.meta_rules, PruneScope::Meta),
                    header_patterns: Self::compile_keyed_patterns(
                        &rule.header_rules,
                        PruneScope::Header,
                    ),
                    cookie_patterns: Self::compile_keyed_patterns(
                        &rule.cookie_rules,
                        PruneScope::Cookie,
                    ),
                    category_ids: rule.tech_info.category_ids.clone(),
                    implies,
                },
            );
            compiled_meta.insert(name, rule.tech_info);
        }

        // 3. 加载分类映射
        let category_map = match category_json_path {
            Some(path) => Self::load_category_map(path),
            None => FxHashMap::default(),
        };

        // 4. 构建证据索引
        let (evidence_index, no_evidence_index) = Self::build_evidence_indexes(&compiled_tech);

        Ok(CompiledRuleLibrary {
            tech_patterns: compiled_tech,
            category_map,
            tech_meta: compiled_meta,
            evidence_index,
            no_evidence_index,
        })
    }

    /// 从指定路径加载分类映射
    /// 参数：json_path - 分类JSON文件路径
    /// 返回：分类ID到名称的映射（空映射表示加载失败）
    pub fn load_category_map(json_path: &str) -> FxHashMap<u32, String> {
        // 读取文件内容
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

        // 解析JSON
        let category_entries: CategoryJsonRoot = match serde_json::from_str(&json_content) {
            Ok(v) => v,
            Err(e) => {
                log::debug!(
                    "Category map JSON parse failed, fallback to empty map | Error: {}",
                    e
                );
                return FxHashMap::default();
            }
        };

        // 构建分类映射
        let mut map = FxHashMap::default();
        for (category_id_str, entry) in category_entries {
            if entry.name.is_empty() {
                continue;
            }

            // 转换分类ID为u32
            match category_id_str.parse::<u32>() {
                Ok(id) => {
                    map.insert(id, entry.name);
                }
                Err(e) => {
                    log::debug!(
                        "Invalid category ID, skipped | ID: {} | Error: {}",
                        category_id_str,
                        e
                    );
                }
            }
        }

        map
    }

    /// 构建证据索引和无证据索引
    /// 参数：compiled_tech - 编译后的技术规则映射
    /// 返回：(证据索引, 无证据索引)
    fn build_evidence_indexes(
        compiled_tech: &FxHashMap<String, CompiledTechRule>,
    ) -> (
        FxHashMap<String, FxHashMap<PruneScope, FxHashSet<String>>>,
        FxHashMap<PruneScope, FxHashSet<String>>,
    ) {
        let mut evidence_index = FxHashMap::default();
        let mut no_evidence_index = FxHashMap::default();

        // 遍历所有技术规则，填充索引
        for (tech_name, tech_rule) in compiled_tech {
            // 填充内容型规则的证据索引
            Self::fill_evidence_index_with_scope(
                tech_name,
                tech_rule.url_patterns.as_ref(),
                PruneScope::Url,
                &mut evidence_index,
            );
            Self::fill_evidence_index_with_scope(
                tech_name,
                tech_rule.html_patterns.as_ref(),
                PruneScope::Html,
                &mut evidence_index,
            );
            Self::fill_evidence_index_with_scope(
                tech_name,
                tech_rule.script_patterns.as_ref(),
                PruneScope::Script,
                &mut evidence_index,
            );

            // 填充KV型规则的证据索引
            Self::fill_evidence_index_for_keyed_with_scope(
                tech_name,
                tech_rule.meta_patterns.as_ref(),
                PruneScope::Meta,
                &mut evidence_index,
            );
            Self::fill_evidence_index_for_keyed_with_scope(
                tech_name,
                tech_rule.header_patterns.as_ref(),
                PruneScope::Header,
                &mut evidence_index,
            );
            Self::fill_evidence_index_for_keyed_with_scope(
                tech_name,
                tech_rule.cookie_patterns.as_ref(),
                PruneScope::Cookie,
                &mut evidence_index,
            );

            // 填充无证据索引
            Self::fill_no_evidence_index_with_scope(tech_name, tech_rule, &mut no_evidence_index);
        }

        (evidence_index, no_evidence_index)
    }

    /// 填充内容型规则的证据索引
    /// 参数：
    /// - tech_name: 技术名称
    /// - patterns: 编译后的匹配模式列表（可选）
    /// - scope: 剪枝作用域
    /// - evidence_map: 证据索引映射（输出参数）
    fn fill_evidence_index_with_scope(
        tech_name: &String,
        patterns: Option<&Vec<CompiledPattern>>,
        scope: PruneScope,
        evidence_map: &mut FxHashMap<String, FxHashMap<PruneScope, FxHashSet<String>>>,
    ) {
        let Some(pats) = patterns else { return };

        for pat in pats {
            // 适配实际的 MatchGate 变体：Open/Anchor/RequireAll/RequireAny
            let evidence_set = match &pat.exec.match_gate {
                MatchGate::Open => FxHashSet::default(), // 无准入条件 → 空集合
                MatchGate::Anchor(_) => FxHashSet::default(), // 锚点剪枝 → 无证据令牌
                MatchGate::RequireAll(set) => set.clone(), // 直接复用已有集合
                MatchGate::RequireAnyLiteral(list) => {
                    // Vec<String> 转 FxHashSet<String>
                    let mut set = FxHashSet::default();
                    list.iter().for_each(|s| {
                        set.insert(s.clone());
                    });
                    set
                }
            };

            if !evidence_set.is_empty() {
                for evidence in evidence_set {
                    evidence_map
                        .entry(evidence.clone())
                        .or_default()
                        .entry(scope)
                        .or_default()
                        .insert(tech_name.clone());
                }
            }
        }
    }

    /// 填充KV型规则的证据索引
    /// 参数：
    /// - tech_name: 技术名称
    /// - keyed_patterns: KV型编译匹配模式（可选）
    /// - scope: 剪枝作用域
    /// - evidence_map: 证据索引映射（输出参数）
    fn fill_evidence_index_for_keyed_with_scope(
        tech_name: &String,
        keyed_patterns: Option<&FxHashMap<String, Vec<CompiledPattern>>>,
        scope: PruneScope,
        evidence_map: &mut FxHashMap<String, FxHashMap<PruneScope, FxHashSet<String>>>,
    ) {
        let Some(keyed_pats) = keyed_patterns else {
            return;
        };

        for (_key, pats) in keyed_pats {
            for pat in pats {
                // 适配实际的 MatchGate 变体
                let evidence_set = match &pat.exec.match_gate {
                    MatchGate::Open => FxHashSet::default(),
                    MatchGate::Anchor(_) => FxHashSet::default(),
                    MatchGate::RequireAll(set) => set.clone(),
                    MatchGate::RequireAnyLiteral(list) => {
                        let mut set = FxHashSet::default();
                        list.iter().for_each(|s| {
                            set.insert(s.clone());
                        });
                        set
                    }
                };

                if !evidence_set.is_empty() {
                    for evidence in evidence_set {
                        evidence_map
                            .entry(evidence.clone())
                            .or_default()
                            .entry(scope)
                            .or_default()
                            .insert(tech_name.clone());
                    }
                }
            }
        }
    }
    /// 填充无证据索引
    /// 参数：
    /// - tech_name: 技术名称
    /// - rule: 编译后的技术规则
    /// - no_evidence_map: 无证据索引映射（输出参数）
    fn fill_no_evidence_index_with_scope(
        tech_name: &String,
        rule: &CompiledTechRule,
        no_evidence_map: &mut FxHashMap<PruneScope, FxHashSet<String>>,
    ) {
        // 判断是否为无证据规则
        let is_no_evidence =
            |cp: &CompiledPattern| !matches!(&cp.exec.match_gate, MatchGate::RequireAll(_));

        // 检查各作用域规则
        if rule
            .url_patterns
            .as_ref()
            .map_or(false, |p| p.iter().any(is_no_evidence))
        {
            no_evidence_map
                .entry(PruneScope::Url)
                .or_default()
                .insert(tech_name.clone());
        }
        if rule
            .html_patterns
            .as_ref()
            .map_or(false, |p| p.iter().any(is_no_evidence))
        {
            no_evidence_map
                .entry(PruneScope::Html)
                .or_default()
                .insert(tech_name.clone());
        }
        if rule
            .script_patterns
            .as_ref()
            .map_or(false, |p| p.iter().any(is_no_evidence))
        {
            no_evidence_map
                .entry(PruneScope::Script)
                .or_default()
                .insert(tech_name.clone());
        }
        if rule
            .meta_patterns
            .as_ref()
            .map_or(false, |k| k.values().any(|p| p.iter().any(is_no_evidence)))
        {
            no_evidence_map
                .entry(PruneScope::Meta)
                .or_default()
                .insert(tech_name.clone());
        }
        if rule
            .header_patterns
            .as_ref()
            .map_or(false, |k| k.values().any(|p| p.iter().any(is_no_evidence)))
        {
            no_evidence_map
                .entry(PruneScope::Header)
                .or_default()
                .insert(tech_name.clone());
        }
        if rule
            .cookie_patterns
            .as_ref()
            .map_or(false, |k| k.values().any(|p| p.iter().any(is_no_evidence)))
        {
            no_evidence_map
                .entry(PruneScope::Cookie)
                .or_default()
                .insert(tech_name.clone());
        }
    }

    /// 编译内容型匹配规则（URL/HTML/Script）
    /// 参数：
    /// - rules: 通用索引规则列表
    /// - scope: 剪枝作用域
    /// 返回：编译后的匹配模式列表（None表示空）
    fn compile_content_patterns(
        rules: &[CommonIndexedRule],
        scope: PruneScope,
    ) -> Option<Vec<CompiledPattern>> {
        let mut pats = Vec::new();

        for r in rules {
            // 构建匹配器
            let matcher = Matcher::from_match_type_lazy(&r.match_type, &r.pattern);
            let matcher_spec = matcher.to_spec();

            // 提取剪枝策略和证据
            let prune_strategy = Self::get_prune_strategy(&matcher);
            let min_evidence = Self::extract_min_evidence_tokens(&matcher);
            let structural_prereq = StructuralPrereq::from_matcher(&matcher);

            // 构建匹配门控
            let match_gate = fold_to_match_gate(prune_strategy, min_evidence, structural_prereq);

            // 添加编译后的模式
            pats.push(CompiledPattern {
                scope,
                index_key: String::new(),
                exec: ExecutablePattern {
                    matcher: matcher_spec,
                    matcher_cache: OnceCell::new(),
                    match_gate,
                    confidence: 100,
                    version_template: r.pattern.version_template.clone(),
                },
            });
        }

        // 空列表返回None
        (!pats.is_empty()).then_some(pats)
    }

    /// 编译KV型匹配规则（Meta/Header/Cookie）
    /// 参数：
    /// - rules: KV型通用索引规则映射
    /// - scope: 剪枝作用域
    /// 返回：编译后的KV型匹配模式（None表示空）
    fn compile_keyed_patterns(
        rules: &FxHashMap<String, Vec<CommonIndexedRule>>,
        scope: PruneScope,
    ) -> Option<FxHashMap<String, Vec<CompiledPattern>>> {
        let mut pats = FxHashMap::default();

        for (k, rs) in rules {
            let mut rule_pats = Vec::new();

            for r in rs {
                // 构建匹配器
                let matcher = Matcher::from_match_type_lazy(&r.match_type, &r.pattern);
                let matcher_spec = matcher.to_spec();

                // 提取剪枝策略和证据
                let prune_strategy = Self::get_prune_strategy(&matcher);
                let min_evidence = Self::extract_min_evidence_tokens(&matcher);
                let structural_prereq = StructuralPrereq::from_matcher(&matcher);

                // 构建匹配门控
                let match_gate =
                    fold_to_match_gate(prune_strategy, min_evidence, structural_prereq);

                // 添加编译后的模式
                rule_pats.push(CompiledPattern {
                    scope,
                    index_key: k.clone(),
                    exec: ExecutablePattern {
                        matcher: matcher_spec,
                        matcher_cache: OnceCell::new(),
                        match_gate,
                        confidence: 100,
                        version_template: r.pattern.version_template.clone(),
                    },
                });
            }

            // 非空列表才插入（Key转为小写）
            if !rule_pats.is_empty() {
                pats.insert(k.to_lowercase(), rule_pats);
            }
        }

        // 空映射返回None
        (!pats.is_empty()).then_some(pats)
    }

    /// 获取匹配器对应的剪枝策略
    /// 参数：matcher - 运行时匹配器
    /// 返回：剪枝策略
    #[inline(always)]
    fn get_prune_strategy(matcher: &Matcher) -> PruneStrategy {
        match matcher {
            Matcher::StartsWith(s) => PruneStrategy::AnchorPrefix(s.to_string()),
            Matcher::Contains(s) => PruneStrategy::Literal(s.to_string()),
            Matcher::LazyRegex { pattern, .. } => {
                prune_strategy::extract_prune_strategy(pattern.as_str())
            }
            Matcher::Exists => PruneStrategy::None,
        }
    }

    /// 提取匹配器的最小证据令牌
    /// 参数：matcher - 运行时匹配器
    /// 返回：最小证据令牌集合
    #[inline(always)]
    fn extract_min_evidence_tokens(matcher: &Matcher) -> FxHashSet<String> {
        match matcher {
            Matcher::Contains(s) | Matcher::StartsWith(s) => {
                let literal = safe_lowercase(s.as_str());
                if literal.len() > 2 {
                    tokenizer::extract_atomic_tokens(&literal)
                } else {
                    FxHashSet::default()
                }
            }
            Matcher::LazyRegex { pattern, .. } => {
                min_evidence::extract_min_evidence_tokens(pattern.as_str())
            }
            Matcher::Exists => FxHashSet::default(),
        }
    }
}
