use crate::{
    rule::core::{MatchType, Pattern, TechBasicInfo},
    utils::{
        min_evidence, prune_analyzer,
        regex_filter::{self, scope_pruner::{self, PruneScope}},
    },
};
use once_cell::sync::Lazy;
use regex::{Captures, Regex, RegexBuilder};
use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::sync::{Arc, RwLock};

/// 全局空正则常量
pub static EMPTY_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^$").unwrap());
/// 全局正则缓存
type RegexCacheKey = (String, bool);
pub static REGEX_CACHE: Lazy<RwLock<FxHashMap<RegexCacheKey, Arc<Regex>>>> =
    Lazy::new(|| RwLock::new(FxHashMap::default()));

// 纯静态匹配规则描述体
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

/// 运行时匹配器
#[derive(Debug, Clone)]
pub enum Matcher {
    Contains(Arc<String>),
    StartsWith(Arc<String>),
    Exists,
    /// 懒加载正则（未编译状态）
    LazyRegex {
        pattern: Arc<String>,
        case_insensitive: bool,
    },
}

impl Matcher {
    /// 从匹配类型+模式构建匹配器（懒加载版本）
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

    // 运行时匹配器 → 静态描述体 转换方法
    pub fn to_spec(&self) -> MatcherSpec {
        match self {
            Matcher::Contains(s) => MatcherSpec::Contains(s.as_str().to_owned()),
            Matcher::StartsWith(s) => MatcherSpec::StartsWith(s.as_str().to_owned()),
            Matcher::Exists => MatcherSpec::Exists,
            Matcher::LazyRegex {
                pattern,
                case_insensitive,
            } => MatcherSpec::Regex {
                pattern: pattern.as_str().to_owned(),
                case_insensitive: *case_insensitive,
            },
        }
    }

    /// 判断是否为Exists类型
    #[inline(always)]
    pub fn is_exists(&self) -> bool {
        matches!(self, Matcher::Exists)
    }

    /// 获取正则捕获组（仅Regex/LazyRegex有效）
    pub fn captures<'a>(&self, input: &'a str) -> Option<Captures<'a>> {
        match self {
            Matcher::LazyRegex {
                pattern: _,
                case_insensitive: _,
            } => {
                // 先编译+缓存正则，保证存在性，再获取捕获组，逻辑无冗余
                let regex = self.get_compiled_regex();
                regex.captures(input)
            }
            _ => None,
        }
    }

    /// 获取编译后的正则，懒加载+缓存，全局复用
    #[inline(always)]
    fn get_compiled_regex(&self) -> Arc<Regex> {
        match self {
            Matcher::LazyRegex {
                pattern,
                case_insensitive,
            } => {
                let cache_key = (pattern.as_str().to_owned(), *case_insensitive);
                let mut cache = REGEX_CACHE.write().unwrap();
                cache
                    .entry(cache_key)
                    .or_insert_with(|| Self::compile_regex(pattern.as_str(), *case_insensitive))
                    .clone()
            }
            _ => Arc::new(EMPTY_REGEX.clone()),
        }
    }

    /// 正则编译公共逻辑
    #[inline]
    fn compile_regex(pattern: &str, case_insensitive: bool) -> Arc<Regex> {
        RegexBuilder::new(pattern)
            .case_insensitive(case_insensitive)
            .build()
            .map_or_else(
                |e| {
                    log::warn!("正则编译失败: 规则={} 错误={}", pattern, e);
                    Arc::new(EMPTY_REGEX.clone())
                },
                |re| Arc::new(re),
            )
    }

    /// 描述匹配器规则（用于日志输出）
    #[inline(always)]
    pub fn describe(&self) -> String {
        match self {
            Matcher::Contains(s) => format!("contains: {}", s),
            Matcher::StartsWith(s) => format!("starts_with: {}", s),
            Matcher::Exists => "exists".to_string(),
            Matcher::LazyRegex { pattern, .. } => format!("lazy_regex: {}", pattern),
        }
    }

    /// 执行匹配（懒编译正则）
    #[inline(always)]
    pub fn matches(&self, input: &str) -> bool {
        match self {
            Matcher::Contains(s) => input.contains(s.as_str()),
            Matcher::StartsWith(s) => input.starts_with(s.as_str()),
            Matcher::Exists => true,
            Matcher::LazyRegex { .. } => self.get_compiled_regex().is_match(input),
        }
    }
}

/// 结构前置条件 ≠ 最小证据，是正则匹配的「准入门槛」，缺失则直接跳过正则执行
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub enum StructuralPrereq {
    /// 必须包含指定子串 (精准命中单一特征)
    RequiresSubstring(String),
    /// 必须包含任意一个子串 (命中OR分支的任意特征，适配你的(?:A|B|C|D)结构)
    RequiresAny(Vec<String>),
    /// 无结构前置条件 (兜底，和原有逻辑对齐)
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

/// 剪枝策略枚举
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PruneStrategy {
    None,                 // 无安全剪枝条件，直接执行正则
    AnchorPrefix(String), // 正则以^开头，匹配串必须前缀命中
    AnchorSuffix(String), // 正则以$结尾，匹配串必须后缀命中
    Exact(String),        // 正则是^xxx$，匹配串必须完全命中
    Literal(String),      // 纯字面量正则(无元字符)，匹配串必须包含命中
}

/// 编译期核心折叠函数
#[inline(always)]
pub fn fold_to_match_gate(
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
        StructuralPrereq::RequiresSubstring(s) => MatchGate::RequireAny(vec![s]),
        StructuralPrereq::RequiresAny(v) if !v.is_empty() => MatchGate::RequireAny(v),
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

// 运行时匹配器 转换方法
impl MatcherSpec {
    #[inline(always)]
    pub fn to_matcher(&self) -> Matcher {
        match self {
            MatcherSpec::Contains(s) => Matcher::Contains(Arc::new(s.clone())),
            MatcherSpec::StartsWith(s) => Matcher::StartsWith(Arc::new(s.clone())),
            MatcherSpec::Exists => Matcher::Exists,
            MatcherSpec::Regex {
                pattern,
                case_insensitive,
            } => Matcher::LazyRegex {
                pattern: Arc::new(pattern.clone()),
                case_insensitive: *case_insensitive,
            },
        }
    }
}

impl CompiledPattern {
    /// 执行匹配 - 内部自动激活Matcher
    #[inline(always)]
    pub fn matches(&self, input: &str) -> bool {
        self.exec.matcher.to_matcher().matches(input)
    }

    /// 剪枝过滤 - 纯业务逻辑，无日志，极致性能
    #[inline(always)]
    pub fn prune_check(&self, input: &str, input_tokens: &FxHashSet<String>) -> bool {
        // 优先级1: 全局黑名单剪枝（原scope/prune_key逻辑，无变动，保留）
        scope_pruner::struct_prune(self.scope, input, Some(&self.index_key))
        // 优先级2: MatchGate统一剪枝校验（收敛 min_evidence_set + prune_strategy）
        && self.exec.match_gate.check(input)
    }

    /// 剪枝 + 匹配 核心方法
    #[inline(always)]
    pub fn matches_with_prune(&self, input: &str, input_tokens: &FxHashSet<String>) -> bool {
        self.prune_check(input, input_tokens) && self.matches(input)
    }

    /// 剪枝 + 匹配 带完整调试日志
    #[inline(always)]
    pub fn matches_with_prune_log(&self, input: &str, input_tokens: &FxHashSet<String>) -> bool {
        self.prune_check_with_log(input, input_tokens) && self.matches(input)
    }

    /// 剪枝过滤，带完整调试日志
    #[inline(always)]
    pub fn prune_check_with_log(&self, input: &str, input_tokens: &FxHashSet<String>) -> bool {
        let preview = Self::compress_for_log(input, 120);
        let matcher_desc = self.exec.matcher.to_matcher().describe();

        // 全局黑名单剪枝，无改动
        if !scope_pruner::struct_prune(self.scope, input, Some(&self.index_key)) {
            log::debug!(
                "黑名单剪枝过滤 | 作用域: {:?} | 输入预览: {} | 长度: {} | 规则:{}",
                self.scope,
                preview,
                input.len(),
                matcher_desc
            );
            return false;
        }

        match &self.exec.match_gate {
            MatchGate::Open => {
                log::debug!(
                    "剪枝兜底放行 | 原因: MatchGate为Open无校验规则 | 输入预览: {} | 规则:{}",
                    preview,
                    matcher_desc
                );
            }
            MatchGate::Anchor(strategy) => {
                if !prune_analyzer::safe_prune_check(input, strategy) {
                    log::debug!(
                        "正则剪枝过滤 | 策略: {:?} | 输入预览: {} | 长度: {} | 规则:{}",
                        strategy,
                        preview,
                        input.len(),
                        matcher_desc
                    );
                    return false;
                }
                log::debug!(
                    "正则剪枝放行 | 策略: {:?} | 输入预览: {} | 规则:{}",
                    strategy,
                    preview,
                    matcher_desc
                );
            }
            MatchGate::RequireAll(set) => {
                let (pass_evidence, missing_evidence) =
                    min_evidence::min_evidence_prune_check_with_missing(set, input_tokens);
                
                if !pass_evidence {
                    log::debug!(
                        "最小证据剪枝过滤 | 输入预览: {} | 证据集: {:?} | 未命中证据: {:?} | 输入令牌: {:?} | 规则:{}",
                        preview,
                        set,
                        missing_evidence,
                        input_tokens,
                        matcher_desc
                    );
                    return false;
                } else {
                    log::debug!(
                        "最小证据剪枝放行 | 原因: {} | 输入预览: {} | 证据集: {:?} | 规则:{}",
                        if set.is_empty() {
                            "证据集为空，兜底放行"
                        } else {
                            "令牌交集命中"
                        },
                        preview,
                        set,
                        matcher_desc
                    );
                }
            }
            MatchGate::RequireAny(list) => {
                let hit = list.iter().any(|token| input.contains(token));
                if !hit {
                    log::debug!(
                        "结构前置剪枝过滤 | 输入预览: {} | 前置条件(任意匹配): {:?} | 规则:{}",
                        preview,
                        list,
                        matcher_desc
                    );
                    return false;
                }
                log::debug!(
                    "结构前置剪枝放行 | 前置条件(任意匹配): {:?} | 输入预览: {} | 规则:{}",
                    list,
                    preview,
                    matcher_desc
                );
            }
        }

        true
    }

    /// 日志内容压缩 - Cow智能无拷贝，短字符串零分配，长字符串按需截断
    #[allow(dead_code)]
    fn compress_for_log(input: &str, max_len: usize) -> Cow<'_, str> {
        if input.len() <= max_len {
            return Cow::Borrowed(input);
        }

        let mut out = String::with_capacity(max_len + 1);
        let mut last_was_space = false;

        for ch in input.chars() {
            if ch.is_whitespace() {
                if !last_was_space {
                    out.push(' ');
                    last_was_space = true;
                }
            } else {
                out.push(ch);
                last_was_space = false;
            }

            if out.len() >= max_len {
                out.push('…');
                break;
            }
        }

        Cow::Owned(out)
    }
}

/// 编译后的技术规则
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
    pub implies: Vec<String>,
}

/// 编译后的规则库
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
