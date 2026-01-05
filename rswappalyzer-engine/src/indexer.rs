use crate::{
    core::{
        CategoryJsonRoot, MatchCondition, MatchRuleSet, MatchScope, MatchType, Pattern,
        TechBasicInfo,
    },
    regex_filter::{self, extract_evidence::safe_lowercase},
    RuleLibrary,
};
use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};
use std::{error::Error, sync::Arc};

/// 全局正则缓存
// use once_cell::sync::Lazy;
// type RegexCacheKey = (String, bool);
// pub static REGEX_CACHE: Lazy<RwLock<FxHashMap<RegexCacheKey, Arc<Regex>>>> =
//     Lazy::new(|| RwLock::new(FxHashMap::default()));

// /// 全局静态空正则，复用避免重复创建，无IO开销，性能优化
// pub static EMPTY_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^$").unwrap());

/// 剪枝作用域枚举 - 枚举所有支持结构化剪枝的业务域
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum PruneScope {
    Url,
    Html,
    Script,
    Header,
    Meta,
    Cookie,
}

/// 剪枝策略枚举
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PruneStrategy {
    None,
    AnchorPrefix(String),
    AnchorSuffix(String),
    Exact(String),
    Literal(String),
}

// 纯静态的匹配规则描述体 - 可序列化、无运行态对象、纯数据载体
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MatcherSpec {
    Contains(String),
    StartsWith(String),
    Exists,
    Regex {
        pattern: String,
        case_insensitive: bool,
    },
}

/// 只负责运行时执行匹配，不参与序列化，彻底与静态数据解耦
#[derive(Debug, Clone)]
pub enum Matcher {
    Contains(Arc<String>),
    StartsWith(Arc<String>),
    Exists,
    LazyRegex {
        pattern: Arc<String>,
        case_insensitive: bool,
    },
}

/// 原始匹配规则集合（接收 parser 输出的原始数据）
#[derive(Debug, Clone)]
pub struct RawMatchSet {
    pub url_patterns: Option<PatternList>,
    pub html_patterns: Option<PatternList>,
    pub script_patterns: Option<PatternList>,
    pub script_src_patterns: Option<PatternList>,
    pub meta_pattern_map: Option<PatternMap>,
    pub header_pattern_map: Option<PatternMap>,
    pub cookie_pattern_map: Option<PatternMap>,
}

/// 列表型模式（url/html/script/script_src）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternList(pub Vec<Pattern>);

/// 键值对型模式（meta/header/cookie）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMap(pub FxHashMap<String, Vec<Pattern>>);

// 索引规则结构体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommonIndexedRule {
    pub tech: String,
    pub match_type: MatchType,
    pub pattern: Pattern,
    pub condition: MatchCondition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScopedIndexedRule {
    KV {
        common: CommonIndexedRule,
        key: String,
    },
    Content(CommonIndexedRule),
}

impl ScopedIndexedRule {
    pub fn common(&self) -> &CommonIndexedRule {
        match self {
            ScopedIndexedRule::KV { common, .. } => common,
            ScopedIndexedRule::Content(common) => common,
        }
    }
}

/// 结构前置条件 ≠ 最小证据，是正则匹配的「准入门槛」，缺失则直接跳过正则执行
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub enum StructuralPrereq {
    /// 必须包含指定子串 (精准命中单一特征)
    RequiresSubstring(String),
    /// 必须包含任意一个子串 (命中OR分支的任意特征，适配(?:A|B|C|D)结构)
    RequiresAny(Vec<String>),
    /// 无结构前置条件
    #[default]
    None,
}
impl StructuralPrereq {
    /// 从Matcher自动提取结构前置条件，编译期执行
    #[inline(always)]
    pub fn from_matcher(matcher: &Matcher) -> Self {
        match matcher {
            Matcher::Contains(s) | Matcher::StartsWith(s) => {
                let s = s.as_str();
                if s.len() > 2 {
                    StructuralPrereq::RequiresSubstring(s.to_string())
                } else {
                    StructuralPrereq::None
                }
            }
            Matcher::LazyRegex { pattern, .. } => {
                let literals =
                    regex_filter::extract_evidence::extract_or_branch_literals(pattern.as_str());
                if literals.len() == 1 {
                    StructuralPrereq::RequiresSubstring(literals.into_iter().next().unwrap())
                } else if literals.len() > 1 {
                    StructuralPrereq::RequiresAny(literals)
                } else {
                    StructuralPrereq::None
                }
            }
            Matcher::Exists => StructuralPrereq::None,
        }
    }
}

/// 编译期核心折叠函数
#[inline(always)]
fn fold_to_match_gate(
    prune_strategy: PruneStrategy,
    min_evidence: FxHashSet<String>,
    structural_prereq: StructuralPrereq,
) -> MatchGate {
    // 优先级1: 锚点剪枝最高，直接返回
    match prune_strategy {
        PruneStrategy::AnchorPrefix(_)
        | PruneStrategy::AnchorSuffix(_)
        | PruneStrategy::Exact(_)
        | PruneStrategy::Literal(_) => {
            return MatchGate::Anchor(prune_strategy);
        }
        _ => {}
    }

    // 优先级2: 最小证据剪枝次之，非空即返回
    if !min_evidence.is_empty() {
        return MatchGate::RequireAll(min_evidence);
    }

    // 优先级3: 结构前置剪枝兜底
    match structural_prereq {
        StructuralPrereq::RequiresSubstring(s) if s.len() >= 3 => MatchGate::RequireAny(vec![s]),
        StructuralPrereq::RequiresAny(v) if !v.is_empty() && v.iter().all(|s| s.len() >= 3) => {
            MatchGate::RequireAny(v)
        }
        _ => MatchGate::Open,
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub enum MatchGate {
    /// 无任何准入条件，直接执行匹配（对应原 None/Exists）
    #[default]
    Open,
    /// 锚点级快速剪枝（优先级最高，对应原 PruneStrategy::AnchorPrefix/AnchorSuffix/Exact）
    Anchor(PruneStrategy),
    /// 最小证据剪枝（交集，铁律，对应原 min_evidence_set，零误杀核心）
    RequireAll(FxHashSet<String>),
    /// 结构前置剪枝（并集，准入门槛，对应原 StructuralPrereq，适配 (A|B|C) 正则）
    RequireAny(Vec<String>),
}

impl MatchGate {
    /// 运行期剪枝校验核心方法 - 内联优化，零开销，短路执行
    #[inline(always)]
    pub fn check(&self, input: &str) -> bool {
        match self {
            MatchGate::Open => true,
            MatchGate::Anchor(strategy) => match strategy {
                PruneStrategy::None => true,
                PruneStrategy::AnchorPrefix(p) => input.starts_with(p),
                PruneStrategy::AnchorSuffix(s) => input.ends_with(s),
                PruneStrategy::Exact(e) => input == e,
                PruneStrategy::Literal(l) => input.contains(l),
            },
            MatchGate::RequireAll(set) => set.iter().all(|token| input.contains(token)),
            MatchGate::RequireAny(list) => list.iter().any(|token| input.contains(token)),
        }
    }
}

/// 核心执行单元, 只负责「如何匹配」
/// 包含：匹配执行体 + 准入网关 + 匹配权重 + 版本模板
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutablePattern {
    pub(crate) matcher: MatcherSpec,
    #[serde(default)]
    pub match_gate: MatchGate,
    pub confidence: u8,
    pub version_template: Option<String>,
}

/// 调度路由单元
/// 包含：调度作用域 + 索引key + 纯净的执行核心
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledPattern {
    pub scope: PruneScope,
    #[serde(default)]
    pub index_key: String,
    pub exec: ExecutablePattern,
}

// 编译后技术规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledTechRule {
    pub name: String,
    pub url_patterns: Option<Vec<CompiledPattern>>,
    pub html_patterns: Option<Vec<CompiledPattern>>,
    pub script_patterns: Option<Vec<CompiledPattern>>,
    pub meta_patterns: Option<FxHashMap<String, Vec<CompiledPattern>>>,
    pub header_patterns: Option<FxHashMap<String, Vec<CompiledPattern>>>,
    pub cookie_patterns: Option<FxHashMap<String, Vec<CompiledPattern>>>,
    pub category_ids: Vec<u32>,
    // 推导技术列表
    pub implies: Vec<String>,
}

// 规则库索引 - 纯静态结构
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleLibraryIndex {
    pub rules: FxHashMap<MatchScope, Vec<ScopedIndexedRule>>,
    pub tech_info_map: FxHashMap<String, TechBasicInfo>,
}

// 编译后规则库
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledRuleLibrary {
    pub tech_patterns: FxHashMap<String, CompiledTechRule>,
    pub category_map: FxHashMap<u32, String>,
    pub tech_meta: FxHashMap<String, TechBasicInfo>,
    // 最小证据关键词 → 对应的技术名称列表，编译期构建，运行期只读
    //pub evidence_to_techs: FxHashMap<String, Vec<String>>,
    // 无最小证据集的技术名集合 → 仅包含Exists/Contains/StartsWith规则的技术
    //pub no_evidence_techs: FxHashSet<String>,
    /// 无最小证据规则（按 scope 维度） scope -> techs
    pub evidence_index: FxHashMap<String, FxHashMap<PruneScope, FxHashSet<String>>>,
    pub no_evidence_index: FxHashMap<PruneScope, FxHashSet<String>>,
}

// 内部构建器
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

struct TechRuleBuilder<'a> {
    tech_info_map: &'a FxHashMap<String, TechBasicInfo>,
    tech_rules: FxHashMap<String, BuiltTechRule>,
}

impl<'a> TechRuleBuilder<'a> {
    fn new(tech_info_map: &'a FxHashMap<String, TechBasicInfo>) -> Self {
        Self {
            tech_info_map,
            tech_rules: FxHashMap::default(),
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
            _ => eprintln!("技术[{}]的{}维度规则类型错误", tech_name, scope),
        }
    }

    fn into_iter(self) -> impl Iterator<Item = (String, BuiltTechRule)> {
        self.tech_rules.into_iter()
    }
}

pub struct RuleIndexer;

impl RuleIndexer {
    pub fn build_compiled_library(
        index: &RuleLibraryIndex,
    ) -> Result<CompiledRuleLibrary, Box<dyn Error>> {
        let mut builder = TechRuleBuilder::new(&index.tech_info_map);
        for (scope, rules) in &index.rules {
            rules.iter().for_each(|r| builder.add_scoped_rule(scope, r));
        }

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
            // 元信息 → 存入 compiled_meta
            compiled_meta.insert(name, rule.tech_info);
        }

        // 加载分类映射并填充
        let category_map = Self::load_category_map("data/categories_data.json")?;

        // 构建「最小证据 → 技术名称」反向索引
        let (evidence_index, no_evidence_index) = Self::build_evidence_indexes(&compiled_tech);

        Ok(CompiledRuleLibrary {
            tech_patterns: compiled_tech,
            category_map,
            tech_meta: compiled_meta,
            evidence_index,
            no_evidence_index,
        })
    }

    fn build_evidence_indexes(
        compiled_tech: &FxHashMap<String, CompiledTechRule>,
    ) -> (
        FxHashMap<String, FxHashMap<PruneScope, FxHashSet<String>>>,
        FxHashMap<PruneScope, FxHashSet<String>>,
    ) {
        // 带维度的最小证据索引：关键词 → 维度 → 技术名集合
        let mut evidence_index = FxHashMap::default();
        // 带维度的无证据索引：维度 → 技术名集合
        let mut no_evidence_index = FxHashMap::default();

        for (tech_name, tech_rule) in compiled_tech {
            // 1. 填充【带维度】的最小证据反向索引
            // 内容型规则 - Url维度
            Self::fill_evidence_index_with_scope(
                tech_name,
                tech_rule.url_patterns.as_ref(),
                PruneScope::Url,
                &mut evidence_index,
            );
            // 内容型规则 - Html维度
            Self::fill_evidence_index_with_scope(
                tech_name,
                tech_rule.html_patterns.as_ref(),
                PruneScope::Html,
                &mut evidence_index,
            );
            // 内容型规则 - Script维度
            Self::fill_evidence_index_with_scope(
                tech_name,
                tech_rule.script_patterns.as_ref(),
                PruneScope::Script,
                &mut evidence_index,
            );

            // 键值型规则 - Meta维度
            Self::fill_evidence_index_for_keyed_with_scope(
                tech_name,
                tech_rule.meta_patterns.as_ref(),
                PruneScope::Meta,
                &mut evidence_index,
            );
            // 键值型规则 - Header维度
            Self::fill_evidence_index_for_keyed_with_scope(
                tech_name,
                tech_rule.header_patterns.as_ref(),
                PruneScope::Header,
                &mut evidence_index,
            );
            // 键值型规则 - Cookie维度
            Self::fill_evidence_index_for_keyed_with_scope(
                tech_name,
                tech_rule.cookie_patterns.as_ref(),
                PruneScope::Cookie,
                &mut evidence_index,
            );

            // 2. 填充【带维度】的无证据反向索引
            Self::fill_no_evidence_index_with_scope(tech_name, tech_rule, &mut no_evidence_index);
        }

        (evidence_index, no_evidence_index)
    }

    // 带维度的内容型最小证据填充
    fn fill_evidence_index_with_scope(
        tech_name: &String,
        patterns: Option<&Vec<CompiledPattern>>,
        scope: PruneScope,
        evidence_map: &mut FxHashMap<String, FxHashMap<PruneScope, FxHashSet<String>>>,
    ) {
        let Some(pats) = patterns else { return };
        for pat in pats {
            // 从MatchGate中提取RequireAll的最小证据集
            if let MatchGate::RequireAll(set) = &pat.exec.match_gate {
                for evidence in set {
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

    // 带维度的键值型最小证据填充
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
                if let MatchGate::RequireAll(set) = &pat.exec.match_gate {
                    for evidence in set {
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

    // 带维度的【无证据】技术填充
    fn fill_no_evidence_index_with_scope(
        tech_name: &String,
        rule: &CompiledTechRule,
        no_evidence_map: &mut FxHashMap<PruneScope, FxHashSet<String>>,
    ) {
        // 判断是否为无证据规则：MatchGate 不是 RequireAll 即为无证据
        let is_no_evidence =
            |cp: &CompiledPattern| !matches!(&cp.exec.match_gate, MatchGate::RequireAll(_));

        // 检查Url维度
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
        // 检查Html维度
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
        // 检查Script维度
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
        // 检查Meta维度
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
        // 检查Header维度
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
        // 检查Cookie维度
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

    // 编译内容型规则，返回MatcherSpec的纯静态列表
    fn compile_content_patterns(
        rules: &[CommonIndexedRule],
        scope: PruneScope,
    ) -> Option<Vec<CompiledPattern>> {
        let mut pats = Vec::new();
        for r in rules {
            let matcher = Matcher::from_match_type_lazy(&r.match_type, &r.pattern);
            let matcher_spec = matcher.to_spec();
            let prune_strategy = Self::get_prune_strategy(&matcher);
            let min_evidence = Self::extract_min_evidence_tokens(&matcher);
            let structural_prereq = StructuralPrereq::from_matcher(&matcher);
            // 编译期折叠为统一的MatchGate
            let match_gate = fold_to_match_gate(prune_strategy, min_evidence, structural_prereq);

            // 1. 构建纯净的执行核心单元
            let exec = ExecutablePattern {
                matcher: matcher_spec,
                match_gate,
                confidence: 100,
                version_template: r.pattern.version_template.clone(),
            };

            // 2. 构建调度路由单元
            pats.push(CompiledPattern {
                scope,
                index_key: String::new(),
                exec,
            });
        }
        if pats.is_empty() {
            None
        } else {
            Some(pats)
        }
    }

    // 编译键值对型规则，返回MatcherSpec的纯静态哈希表
    fn compile_keyed_patterns(
        rules: &FxHashMap<String, Vec<CommonIndexedRule>>,
        scope: PruneScope,
    ) -> Option<FxHashMap<String, Vec<CompiledPattern>>> {
        let mut pats = FxHashMap::default();
        for (k, rs) in rules {
            let mut rule_pats = Vec::new();
            for r in rs {
                let matcher = Matcher::from_match_type_lazy(&r.match_type, &r.pattern);
                let matcher_spec = matcher.to_spec();
                let prune_strategy = Self::get_prune_strategy(&matcher);
                let min_evidence = Self::extract_min_evidence_tokens(&matcher);
                let structural_prereq = StructuralPrereq::from_matcher(&matcher);
                let match_gate =
                    fold_to_match_gate(prune_strategy, min_evidence, structural_prereq);

                let exec = ExecutablePattern {
                    matcher: matcher_spec,
                    match_gate,
                    confidence: 100,
                    version_template: r.pattern.version_template.clone(),
                };

                rule_pats.push(CompiledPattern {
                    scope,
                    index_key: k.clone(),
                    exec,
                });
            }
            if !rule_pats.is_empty() {
                pats.insert(k.to_lowercase(), rule_pats);
            }
        }
        if pats.is_empty() {
            None
        } else {
            Some(pats)
        }
    }

    /// 从指定路径加载分类映射
    pub fn load_category_map(json_path: &str) -> Result<FxHashMap<u32, String>, Box<dyn Error>> {
        let json_content = std::fs::read_to_string(json_path)
            .map_err(|e| format!("读取分类JSON失败: {} | 路径: {}", e, json_path))?;

        let category_entries: CategoryJsonRoot = serde_json::from_str(&json_content)
            .map_err(|e| format!("反序列化分类JSON失败: {}", e))?;

        let category_map = category_entries
            .into_iter()
            .filter(|(_, entry)| !entry.name.is_empty())
            .map(|(category_id_str, entry)| {
                let category_id = category_id_str.parse::<u32>().map_err(|e| {
                    format!(
                        "分类ID格式错误: {} 不是合法数字, 错误: {}",
                        category_id_str, e
                    )
                })?;
                Ok((category_id, entry.name))
            })
            .collect::<Result<FxHashMap<u32, String>, Box<dyn Error>>>()?;

        Ok(category_map)
    }

    // 剪枝策略分析
    #[inline(always)]
    fn get_prune_strategy(matcher: &Matcher) -> PruneStrategy {
        match matcher {
            // StartsWith → 前缀锚定剪枝，最优策略
            Matcher::StartsWith(s) => PruneStrategy::AnchorPrefix(s.to_string()),
            // Contains → 字面量匹配剪枝，精准高效
            Matcher::Contains(s) => PruneStrategy::Literal(s.to_string()),
            // 正则 → 调用工具层的剪枝策略分析
            Matcher::LazyRegex { pattern, .. } => {
                regex_filter::prune_analyzer::analyze_prune_strategy(pattern.as_str())
            }
            // Exists → 无剪枝策略
            Matcher::Exists => PruneStrategy::None,
        }
    }

    // 最小证据token提取
    #[inline(always)]
    fn extract_min_evidence_tokens(matcher: &Matcher) -> FxHashSet<String> {
        match matcher {
            Matcher::Contains(s) | Matcher::StartsWith(s) => {
                // 显式解引用Arc<String>为&str，小写转换
                let literal = safe_lowercase(s.as_str());
                if literal.len() > 2 {
                    regex_filter::extract_evidence::split_to_atomic_tokens(&literal)
                } else {
                    FxHashSet::default()
                }
            }
            // 正则类型：调用工具层的纯通用提取逻辑
            Matcher::LazyRegex { pattern, .. } => {
                regex_filter::extract_evidence::extract_min_evidence_tokens(pattern.as_str())
            }
            // Exists：无证据，返回空集
            Matcher::Exists => FxHashSet::default(),
        }
    }
}

// RuleLibraryIndex
impl RuleLibraryIndex {
    pub fn from_rule_library(rule_lib: &RuleLibrary) -> Result<Self, Box<dyn Error>> {
        let mut index = Self::default();
        for (tech_id, rule) in &rule_lib.core_tech_map {
            index
                .tech_info_map
                .insert(tech_id.clone(), rule.basic.clone());
            for (scope, set) in &rule.match_rules {
                let scoped_rules = Self::build_scoped_indexed_rules(tech_id.clone(), set, scope)?;
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
        set: &MatchRuleSet,
        scope: &MatchScope,
    ) -> Result<Vec<ScopedIndexedRule>, Box<dyn Error>> {
        let mut rules = Vec::new();
        match scope {
            MatchScope::Header | MatchScope::Cookie | MatchScope::Meta => {
                set.keyed_patterns.iter().for_each(|kp| {
                    rules.push(ScopedIndexedRule::KV {
                        common: CommonIndexedRule {
                            tech: tech_id.clone(),
                            match_type: kp.pattern.match_type.clone(),
                            pattern: kp.pattern.clone(),
                            condition: set.condition.clone(),
                        },
                        key: kp.key.clone(),
                    });
                });
            }
            _ => {
                set.list_patterns.iter().for_each(|p| {
                    rules.push(ScopedIndexedRule::Content(CommonIndexedRule {
                        tech: tech_id.clone(),
                        match_type: p.match_type.clone(),
                        pattern: p.clone(),
                        condition: set.condition.clone(),
                    }));
                });
            }
        }
        Ok(rules)
    }
}

// 运行时匹配器 → 静态描述体
impl Matcher {
    pub fn to_spec(&self) -> MatcherSpec {
        match self {
            Matcher::Contains(s) => MatcherSpec::Contains(s.to_string()),
            Matcher::StartsWith(s) => MatcherSpec::StartsWith(s.to_string()),
            Matcher::Exists => MatcherSpec::Exists,
            // Matcher::Regex(re) => MatcherSpec::Regex {
            //     pattern: re.as_str().to_string(),
            //     case_insensitive: self.case_insensitive(),
            // },
            Matcher::LazyRegex {
                pattern,
                case_insensitive,
            } => MatcherSpec::Regex {
                pattern: pattern.to_string(),
                case_insensitive: *case_insensitive,
            },
        }
    }

    // 从匹配类型构建懒加载匹配器
    pub fn from_match_type_lazy(match_type: &MatchType, pattern: &Pattern) -> Self {
        match match_type {
            MatchType::Contains => Self::Contains(Arc::new(pattern.pattern.clone())),
            MatchType::StartsWith => Self::StartsWith(Arc::new(pattern.pattern.clone())),
            MatchType::Exists => Self::Exists,
            MatchType::Regex => Self::LazyRegex {
                pattern: Arc::new(pattern.pattern.clone()),
                case_insensitive: true,
            },
        }
    }

    /// 从静态MatcherSpec还原运行态Matcher
    pub fn from_spec(spec: &MatcherSpec) -> Self {
        match spec {
            MatcherSpec::Contains(s) => Self::Contains(Arc::new(s.clone())),
            MatcherSpec::StartsWith(s) => Self::StartsWith(Arc::new(s.clone())),
            MatcherSpec::Exists => Self::Exists,
            MatcherSpec::Regex {
                pattern,
                case_insensitive,
            } => Self::LazyRegex {
                pattern: Arc::new(pattern.clone()),
                case_insensitive: *case_insensitive,
            },
        }
    }
}
