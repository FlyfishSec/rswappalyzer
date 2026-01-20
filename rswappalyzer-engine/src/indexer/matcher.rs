use crate::{
    MatchGate, compiled::{LiteralId, LiteralInterner, PatternEvidence}, core::Pattern,
};
use once_cell::sync::Lazy;
use regex::{Captures, Regex, RegexBuilder};
use rustc_hash::{FxHashMap, FxHashSet};
use std::{
    sync::{Arc, RwLock},
};

/// 全局空正则常量（预编译，用于错误回退）
pub static EMPTY_REGEX_ARC: Lazy<Arc<Regex>> = Lazy::new(|| Arc::new(Regex::new(r"^$").unwrap())); // 安全unwrap：r"^$"是语法合法的极简正则，编译永不失败

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
    /// 包含匹配（子字符串）- 已从 Arc<String> 改为 LiteralId
    Contains(LiteralId),

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
                // 构建缓存Key
                let cache_key = (pattern.clone(), *case_insensitive); // Arc clone

                // 1. 读锁查询缓存（无锁竞争）
                // 读锁：正常逻辑下锁不会毒化，unwrap安全（毒化属于程序异常，需panic暴露）
                let cache_read = REGEX_CACHE.read().unwrap();
                if let Some(re) = cache_read.get(&cache_key) {
                    return re.clone(); // Arc clone
                }
                drop(cache_read); // 显式释放读锁

                // 2. 写锁编译并插入缓存（仅缓存未命中时执行）
                // 写锁：正常逻辑下锁不会毒化，unwrap安全（毒化属于程序异常，需panic暴露）
                let mut cache_write = REGEX_CACHE.write().unwrap();
                cache_write
                    .entry(cache_key)
                    .or_insert_with(|| Self::compile_regex(pattern.as_str(), *case_insensitive))
                    .clone() // Arc clone
            }
            // 非正则类型返回全局空正则
            _ => EMPTY_REGEX_ARC.clone(), // arc clone
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
                    EMPTY_REGEX_ARC.clone() // Arc clone 回退到空正则
                },
                |re| Arc::new(re),
            )
    }

    /// 描述匹配器规则（用于日志/调试输出）
    #[inline(always)]
    pub fn describe(&self, literal_interner: &LiteralInterner) -> String {
        match self {
            Matcher::Contains(lit_id) => {
                let literal = literal_interner.get_literal(*lit_id).unwrap_or("unknown");
                format!("contains: {} (id: {})", literal, lit_id.0)
            }
            Matcher::Exists => "exists".to_string(),
            Matcher::LazyRegex { pattern, .. } => format!("lazy_regex: {}", pattern),
        }
    }
    // pub fn describe(&self) -> String {
    //     match self {
    //         Matcher::Contains(s) => format!("contains: {}", s),
    //         Matcher::Exists => "exists".to_string(),
    //         Matcher::LazyRegex { pattern, .. } => format!("lazy_regex: {}", pattern),
    //     }
    // }

    /// 执行匹配
    #[inline(always)]
    pub fn matches(&self, input: &str, contains_hit_ids: &FxHashSet<LiteralId>) -> bool {
        match self {
            Matcher::Contains(lid) => contains_hit_ids.contains(lid),
            Matcher::Exists => true,
            Matcher::LazyRegex { .. } => self.get_compiled_regex().is_match(input),
        }
    }
    // pub fn matches<T: Eq + Hash + Borrow<str>>(
    //     &self,
    //     input: &str,
    //     contains_hit_lc: &FxHashSet<T>,
    // ) -> bool {
    //     match self {
    //         // contains_hit_lc 中的 T 能 Borrow<str>，因此可以匹配 &str 类型的查找值
    //         Matcher::Contains(s) => contains_hit_lc.contains(s.as_str()),
    //         Matcher::Exists => true,
    //         Matcher::LazyRegex { .. } => self.get_compiled_regex().is_match(input),
    //     }
    // }

    /// 转换为静态匹配器描述体（用于序列化）
    pub fn to_spec(&self) -> super::MatcherSpec {
        match self {
            Matcher::Contains(lid) => super::MatcherSpec::Contains(*lid),
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
    /// - match_type: 匹配类型（Contains/Exists/Regex）
    /// - pattern: 匹配模式
    /// 返回：运行时匹配器实例
    // pub fn from_match_type_lazy(
    //     match_type: &MatchType,
    //     pattern: &Pattern,
    //     literal_id: Option<LiteralId>,
    // ) -> Self {
    //     match match_type {
    //         //MatchType::Contains => Self::Contains(Arc::new(pattern.pattern.clone())), // Arc clone
    //         MatchType::Contains => Self::Contains(literal_id),
    //         MatchType::Exists => Self::Exists,
    //         MatchType::Regex => Self::LazyRegex {
    //             pattern: Arc::new(pattern.pattern.clone()), // Arc clone
    //             case_insensitive: true,
    //         },
    //     }
    // }

    // Contains 类型：强制传 LiteralId
    pub fn from_contains(literal_id: LiteralId) -> Self {
        Self::Contains(literal_id)
    }

    // Exists 类型：无参数
    pub fn from_exists() -> Self {
        Self::Exists
    }

    // Regex 类型：只传需要的参数
    pub fn from_regex(pattern: &Pattern, case_insensitive: bool) -> Self {
        Self::LazyRegex {
            pattern: Arc::new(pattern.pattern.clone()),
            case_insensitive,
        }
    }

    /// 从静态MatcherSpec还原运行态Matcher
    /// 参数：spec - 静态匹配器描述体
    /// 返回：运行时匹配器实例
    pub fn from_spec(spec: &super::MatcherSpec) -> Self {
        match spec {
            super::MatcherSpec::Contains(lid) => Self::Contains(*lid),
            super::MatcherSpec::Exists => Self::Exists,
            super::MatcherSpec::Regex {
                pattern,
                case_insensitive,
            } => Self::LazyRegex {
                pattern: Arc::new(pattern.clone()), // Arc clone
                case_insensitive: *case_insensitive,
            },
        }
    }
}

// /// 结构前置条件扩展方法
// impl StructuralPrereq {
//     /// 从Matcher自动提取结构前置条件（编译期执行）
//     /// 核心逻辑：
//     /// 1. 短字符串（≤2）：返回None
//     /// 2. 长字符串：返回RequiresSubstring
//     /// 3. 正则：提取OR分支字面量，返回RequiresSubstring/RequiresAny
//     pub fn from_matcher(matcher: &Matcher, literal_interner: &LiteralInterner) -> Self {
//         match matcher {
//             Matcher::Contains(lid) => {
//                 if let Some(s) = literal_interner.get_literal(*lid) {
//                     if s.len() > 2 {
//                         StructuralPrereq::RequiresSubstring(s.to_string())
//                     } else {
//                         StructuralPrereq::None
//                     }
//                 } else {
//                     StructuralPrereq::None
//                 }
//                 // let s = s.as_str();
//                 // if s.len() > 2 {
//                 //     StructuralPrereq::RequiresSubstring(s.to_string())
//                 // } else {
//                 //     StructuralPrereq::None
//                 // }
//             }

//             Matcher::LazyRegex { pattern, .. } => {
//                 let pattern_str = pattern.as_str();

//                 // 提取语义安全的特征
//                 let safe_features = extract_semantic_safe_features(pattern_str);

//                 // 根据安全特征生成结构前置
//                 match safe_features.len() {
//                     // 单个特征 → 精准子串匹配
//                     1 => StructuralPrereq::RequiresSubstring(
//                         safe_features.into_iter().next().unwrap(),
//                     ),
//                     // 多个特征 → OR分支匹配
//                     n if n > 1 => StructuralPrereq::RequiresAny(safe_features),
//                     // 无特征 → 无前置条件
//                     _ => StructuralPrereq::None,
//                 }
//             }

//             // 3. Exists类型：无前置条件
//             Matcher::Exists => StructuralPrereq::None,
//         }
//     }
// }

/// 将PatternEvidence折叠为匹配门（MatchGate）
/// 核心逻辑：基于已提取的字面量分级判定匹配策略
// 常量定义：匹配策略阈值（统一管理，便于后续调整）
const STR_MIN_VALID_LEN: usize = 3; // 字符串最小有效长度
const ANY_LIST_QUALITY_FILTER_MIN_TOTAL: usize = 3; // Any列表过滤最小总数
const ANY_LIST_HIGH_QUALITY_ITEM_MIN_COUNT: usize = 2; // 高质量项最小数量
const ANY_LIST_HIGH_QUALITY_ITEM_MIN_LEN: usize = 4; // 高质量项最小长度
const HIGH_CONFIDENCE_LEN_THRESHOLD: usize = 6; // 高置信度长度阈值

pub fn fold_to_match_gate(evidence: &PatternEvidence) -> MatchGate {
    let mut literals = evidence.literals.clone();
    let mut structural_any_list = evidence.any_literals.clone();

    // 预处理最小证据字面量
    // 1. 过滤无效项：仅保留长度≥最小有效长度的字面量
    literals.retain(|s| s.len() >= STR_MIN_VALID_LEN);

    // 2. 核心判断条件计算
    // 最小证据字面量有效性：非空且至少有一个有效字面量
    let has_valid_literals = !literals.is_empty();
    // 3. 高置信度判定：存在2个以上 或 有超长字面量（>6）
    let has_long_literal = literals.iter().any(|s| s.len() > HIGH_CONFIDENCE_LEN_THRESHOLD);
    let is_high_confidence = literals.len() > 1 || has_long_literal;

    // 预处理Any列表
    // 1. 过滤无效项
    structural_any_list.retain(|s| s.len() >= STR_MIN_VALID_LEN);
    
    // 2. 质量过滤（仅当满足数量条件时执行）
    let total_valid_any = structural_any_list.len();
    let high_quality_any_count = structural_any_list
        .iter()
        .filter(|s| s.len() > ANY_LIST_HIGH_QUALITY_ITEM_MIN_LEN)
        .count();
    
    let should_filter_any = total_valid_any >= ANY_LIST_QUALITY_FILTER_MIN_TOTAL 
        && high_quality_any_count >= ANY_LIST_HIGH_QUALITY_ITEM_MIN_COUNT;
    
    if should_filter_any {
        structural_any_list.retain(|s| s.len() > ANY_LIST_HIGH_QUALITY_ITEM_MIN_LEN);
    }

    // 处理空列表
    let any_literals = if structural_any_list.is_empty() {
        None
    } else {
        Some(structural_any_list)
    };

    // 匹配门构建
    if is_high_confidence {
        // 场景1：高置信度 → 使用全部最小证据字面量（用于交集判断）
        MatchGate {
            require_literals: if has_valid_literals { Some(literals) } else { None },
            require_literal_ids: None,
            require_any_literals: None,
            require_any_literal_ids: None,
        }
    } else {
        // 场景2：低置信度 → 使用Any字面量（并集判断）
        MatchGate {
            require_literals: None,
            require_literal_ids: None,
            require_any_literals: any_literals,
            require_any_literal_ids: None,
        }
    }
}