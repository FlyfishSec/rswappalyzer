use crate::{
    core::{MatchType, Pattern},
    prune_strategy::PruneStrategy,
    regex_literal::{self, extract_or_branch_literals},
};
use once_cell::sync::Lazy;
use regex::{Captures, Regex, RegexBuilder};
use rustc_hash::{FxHashMap, FxHashSet};
use std::sync::{Arc, RwLock};

/// 全局空正则常量（预编译，用于错误回退）
/// 零拷贝、零分配，全局复用
pub static EMPTY_REGEX_ARC: Lazy<Arc<Regex>> = Lazy::new(|| Arc::new(Regex::new(r"^$").unwrap()));

/// 全局正则缓存类型定义
/// Key: (正则模式字符串, 是否忽略大小写)
/// Value: 编译后的正则Arc（避免重复编译）
type RegexCacheKey = (Arc<String>, bool);
pub static REGEX_CACHE: Lazy<RwLock<FxHashMap<RegexCacheKey, Arc<Regex>>>> =
    Lazy::new(|| RwLock::new(FxHashMap::default()));

/// 运行时匹配器（非序列化）
/// 核心特性：
/// 1. 懒加载编译正则（首次匹配时编译）
/// 2. 全局正则缓存（避免重复编译）
/// 3. Arc封装字符串（零拷贝）
/// 4. 高性能匹配逻辑（inline优化）
#[derive(Debug, Clone)]
pub enum Matcher {
    /// 包含匹配（子字符串）
    Contains(Arc<String>),
    /// 前缀匹配（以指定字符串开头）
    StartsWith(Arc<String>),
    /// 存在匹配（始终返回true）
    Exists,
    /// 懒加载正则匹配
    LazyRegex {
        /// 正则模式字符串（Arc封装）
        pattern: Arc<String>,
        /// 是否忽略大小写
        case_insensitive: bool,
    },
}

impl Matcher {
    /// 判断是否为Exists类型匹配器
    #[inline(always)]
    pub fn is_exists(&self) -> bool {
        matches!(self, Matcher::Exists)
    }

    /// 获取正则捕获组（仅LazyRegex类型有效）
    /// 参数：input - 待匹配的字符串
    /// 返回：捕获组结果（None表示非正则类型/无匹配）
    pub fn captures<'a>(&self, input: &'a str) -> Option<Captures<'a>> {
        match self {
            Matcher::LazyRegex { .. } => self.get_compiled_regex().captures(input),
            _ => None,
        }
    }

    /// 获取编译后的正则（懒加载+全局缓存）
    /// 核心逻辑：读锁查缓存 → 未命中则写锁编译并缓存
    #[inline(always)]
    fn get_compiled_regex(&self) -> Arc<Regex> {
        match self {
            Matcher::LazyRegex {
                pattern,
                case_insensitive,
            } => {
                // 构建缓存Key（Arc clone仅增加引用计数，零拷贝）
                let cache_key = (pattern.clone(), *case_insensitive);
                
                // 1. 读锁查询缓存（无锁竞争）
                let cache_read = REGEX_CACHE.read().unwrap();
                if let Some(re) = cache_read.get(&cache_key) {
                    return re.clone();
                }
                drop(cache_read); // 显式释放读锁

                // 2. 写锁编译并插入缓存（仅缓存未命中时执行）
                let mut cache_write = REGEX_CACHE.write().unwrap();
                cache_write
                    .entry(cache_key)
                    .or_insert_with(|| Self::compile_regex(pattern.as_str(), *case_insensitive))
                    .clone()
            }
            // 非正则类型返回全局空正则（零拷贝）
            _ => EMPTY_REGEX_ARC.clone(),
        }
    }

    /// 正则编译公共逻辑（带错误处理）
    /// 参数：
    /// - pattern: 正则模式字符串
    /// - case_insensitive: 是否忽略大小写
    /// 返回：编译后的正则Arc（失败则返回空正则）
    #[inline]
    fn compile_regex(pattern: &str, case_insensitive: bool) -> Arc<Regex> {
        RegexBuilder::new(pattern)
            .case_insensitive(case_insensitive)
            .build()
            .map_or_else(
                |e| {
                    log::warn!("Regex compilation failed: pattern={} error={}", pattern, e);
                    EMPTY_REGEX_ARC.clone() // 回退到空正则
                },
                |re| Arc::new(re),
            )
    }

    /// 描述匹配器规则（用于日志/调试输出）
    #[inline(always)]
    pub fn describe(&self) -> String {
        match self {
            Matcher::Contains(s) => format!("contains: {}", s),
            Matcher::StartsWith(s) => format!("starts_with: {}", s),
            Matcher::Exists => "exists".to_string(),
            Matcher::LazyRegex { pattern, .. } => format!("lazy_regex: {}", pattern),
        }
    }

    /// 执行匹配（核心匹配逻辑）
    /// 参数：input - 待匹配的字符串
    /// 返回：匹配结果（bool）
    #[inline(always)]
    pub fn matches(&self, input: &str) -> bool {
        match self {
            Matcher::Contains(s) => input.contains(s.as_str()),
            Matcher::StartsWith(s) => input.starts_with(s.as_str()),
            Matcher::Exists => true,
            Matcher::LazyRegex { .. } => self.get_compiled_regex().is_match(input),
        }
    }

    /// 转换为静态匹配器描述体（用于序列化）
    pub fn to_spec(&self) -> super::MatcherSpec {
        match self {
            Matcher::Contains(s) => super::MatcherSpec::Contains(s.to_string()),
            Matcher::StartsWith(s) => super::MatcherSpec::StartsWith(s.to_string()),
            Matcher::Exists => super::MatcherSpec::Exists,
            Matcher::LazyRegex {
                pattern,
                case_insensitive,
            } => super::MatcherSpec::Regex {
                pattern: pattern.to_string(),
                case_insensitive: *case_insensitive,
            },
        }
    }

    /// 从匹配类型构建懒加载匹配器
    /// 参数：
    /// - match_type: 匹配类型（Contains/StartsWith/Exists/Regex）
    /// - pattern: 匹配模式
    /// 返回：运行时匹配器实例
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
    /// 参数：spec - 静态匹配器描述体
    /// 返回：运行时匹配器实例
    pub fn from_spec(spec: &super::MatcherSpec) -> Self {
        match spec {
            super::MatcherSpec::Contains(s) => Self::Contains(Arc::new(s.clone())),
            super::MatcherSpec::StartsWith(s) => Self::StartsWith(Arc::new(s.clone())),
            super::MatcherSpec::Exists => Self::Exists,
            super::MatcherSpec::Regex {
                pattern,
                case_insensitive,
            } => Self::LazyRegex {
                pattern: Arc::new(pattern.clone()),
                case_insensitive: *case_insensitive,
            },
        }
    }
}

/// 结构前置条件扩展方法
impl super::StructuralPrereq {
    /// 从Matcher自动提取结构前置条件（编译期执行）
    /// 核心逻辑：
    /// 1. 短字符串（≤2）：返回None
    /// 2. 长字符串：返回RequiresSubstring
    /// 3. 正则：提取OR分支字面量，返回RequiresSubstring/RequiresAny
    pub fn from_matcher(matcher: &Matcher) -> Self {
        match matcher {
            Matcher::Contains(s) | Matcher::StartsWith(s) => {
                let s = s.as_str();
                if s.len() > 2 {
                    super::StructuralPrereq::RequiresSubstring(s.to_string())
                } else {
                    super::StructuralPrereq::None
                }
            }
            Matcher::LazyRegex { pattern, .. } => {
                // 快速判断：无OR分支的正则直接返回None（80%场景优化）
                if !pattern.contains("(?:") || !pattern.contains('|') {
                    return super::StructuralPrereq::None;
                }

                let mut literals = extract_or_branch_literals(pattern.as_str());
                match literals.len() {
                    1 => super::StructuralPrereq::RequiresSubstring(literals.swap_remove(0)),
                    n if n > 1 => super::StructuralPrereq::RequiresAny(literals),
                    _ => super::StructuralPrereq::None,
                }
            }
            Matcher::Exists => super::StructuralPrereq::None,
        }
    }

    /// 旧版结构前置条件提取逻辑（兼容用）
    #[inline(always)]
    pub fn from_matcher_old(matcher: &Matcher) -> Self {
        match matcher {
            Matcher::Contains(s) | Matcher::StartsWith(s) => {
                let s = s.as_str();
                if s.len() > 2 {
                    super::StructuralPrereq::RequiresSubstring(s.to_string())
                } else {
                    super::StructuralPrereq::None
                }
            }
            Matcher::LazyRegex { pattern, .. } => {
                let literals = regex_literal::extract_or_branch_literals(pattern.as_str());
                if literals.len() == 1 {
                    super::StructuralPrereq::RequiresSubstring(literals.into_iter().next().unwrap())
                } else if literals.len() > 1 {
                    super::StructuralPrereq::RequiresAny(literals)
                } else {
                    super::StructuralPrereq::None
                }
            }
            Matcher::Exists => super::StructuralPrereq::None,
        }
    }
}

/// 编译期核心折叠函数（生成匹配门控）
/// 优先级：锚点剪枝 > 最小证据剪枝 > 结构前置剪枝 > 开放匹配
/// 参数：
/// - prune_strategy: 剪枝策略
/// - min_evidence: 最小证据集合
/// - structural_prereq: 结构前置条件
/// 返回：匹配门控实例
#[inline(always)]
pub fn fold_to_match_gate(
    prune_strategy: PruneStrategy,
    min_evidence: FxHashSet<String>,
    structural_prereq: super::StructuralPrereq,
) -> super::MatchGate {
    // 优先级1: 锚点剪枝（最高优先级）
    match prune_strategy {
        PruneStrategy::AnchorPrefix(_)
        | PruneStrategy::AnchorSuffix(_)
        | PruneStrategy::Exact(_)
        | PruneStrategy::Literal(_) => {
            return super::MatchGate::Anchor(prune_strategy);
        }
        _ => {}
    }

    // 优先级2: 最小证据剪枝（非空即返回）
    if !min_evidence.is_empty() {
        return super::MatchGate::RequireAll(min_evidence);
    }

    // 优先级3: 结构前置剪枝（兜底）
    match structural_prereq {
        super::StructuralPrereq::RequiresSubstring(s) if s.len() >= 3 => {
            super::MatchGate::RequireAnyLiteral(vec![s])
        }
        super::StructuralPrereq::RequiresAny(v)
            if !v.is_empty() && v.iter().all(|s| s.len() >= 3) =>
        {
            super::MatchGate::RequireAnyLiteral(v)
        }
        _ => super::MatchGate::Open,
    }
}