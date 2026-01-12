use crate::{
    core::{MatchType, Pattern},
    min_evidence::MinEvidenceMeta,
    regex_literal::extract_semantic_safe_features,
    MatchGate, StructuralPrereq,
};
use once_cell::sync::Lazy;
use regex::{Captures, Regex, RegexBuilder};
use rustc_hash::FxHashMap;
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
            Matcher::Exists => true,
            Matcher::LazyRegex { .. } => self.get_compiled_regex().is_match(input),
        }
    }

    /// 转换为静态匹配器描述体（用于序列化）
    pub fn to_spec(&self) -> super::MatcherSpec {
        match self {
            Matcher::Contains(s) => super::MatcherSpec::Contains(s.to_string()),
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
    pub fn from_match_type_lazy(match_type: &MatchType, pattern: &Pattern) -> Self {
        match match_type {
            MatchType::Contains => Self::Contains(Arc::new(pattern.pattern.clone())),
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
impl StructuralPrereq {
    /// 从Matcher自动提取结构前置条件（编译期执行）
    /// 核心逻辑：
    /// 1. 短字符串（≤2）：返回None
    /// 2. 长字符串：返回RequiresSubstring
    /// 3. 正则：提取OR分支字面量，返回RequiresSubstring/RequiresAny

    pub fn from_matcher(matcher: &Matcher) -> Self {
        match matcher {
            Matcher::Contains(s) => {
                let s = s.as_str();
                if s.len() > 2 {
                    StructuralPrereq::RequiresSubstring(s.to_string())
                } else {
                    StructuralPrereq::None
                }
            }

            Matcher::LazyRegex { pattern, .. } => {
                let pattern_str = pattern.as_str();

                // 仅调用一次：提取语义安全的特征
                let safe_features = extract_semantic_safe_features(pattern_str);

                // 根据安全特征生成结构前置
                match safe_features.len() {
                    // 单个特征 → 精准子串匹配
                    1 => StructuralPrereq::RequiresSubstring(
                        safe_features.into_iter().next().unwrap(),
                    ),
                    // 多个特征 → OR分支匹配
                    n if n > 1 => StructuralPrereq::RequiresAny(safe_features),
                    // 无特征 → 无前置条件
                    _ => StructuralPrereq::None,
                }
            }

            // 3. Exists类型：无前置条件
            Matcher::Exists => StructuralPrereq::None,
        }
    }
}

/// 将最小证据元数据和结构前置条件折叠为匹配门（MatchGate）
/// 核心逻辑：基于token数量/密度、字面量有效性分级判定匹配策略，
/// 高置信度场景优先使用token匹配，低置信度场景降级为字面量/结构匹配
pub fn fold_to_match_gate_old(
    min_evidence_meta: MinEvidenceMeta,
    structural_prereq: StructuralPrereq,
) -> MatchGate {
    // ========== 1. 提取核心数据（解构元数据，减少重复访问） ==========
    // 证据元数据中的token列表
    let tokens = min_evidence_meta.tokens;
    // token列表的长度（用于判定token数量阈值）
    let token_len = tokens.len();
    // 源字面量（原始匹配文本）
    let source_literal = min_evidence_meta.source_literal;
    // 源字面量的长度（用于判定字面量有效性）
    let source_literal_len = source_literal.len();
    // 源文本总长度（判定是否存在有效字面量的基础）
    let has_literal = min_evidence_meta.source_len > 0;

    // ========== 2. 高置信度token判定逻辑（核心分级条件） ==========
    // 判定是否满足“多token”条件（token数量≥3）
    let has_many_tokens = token_len >= 3;
    // 计算所有token的总长度（用于判定token密度）
    let total_token_len: usize = tokens.iter().map(|t| t.len()).sum();
    // 判定token是否“密集”：多token且总长度≥6（保证token具备足够辨识度）
    let tokens_dense = has_many_tokens && total_token_len >= 6;

    // ========== 3. 核心置信度判断 ==========
    // 是否需要验证字面量：存在有效字面量但token数量≤1（token不足，需兜底）
    let need_verify_literal = has_literal && token_len <= 1;
    // 高置信度判定：无需验证字面量，且满足“有有效字面量”或“token密集”
    // 注意：此处“高置信度”仅表示“可尝试token匹配”，不代表匹配结果100%准确
    let is_high_confidence = !need_verify_literal && (has_literal || tokens_dense);

    // ========== 4. 预处理结构前置条件（过滤无效的any列表项） ==========
    // 提取有效的结构any列表：仅保留长度≥2的字符串（短字符串无匹配价值）
    let structural_any_list = match structural_prereq {
        // 子串要求：仅当子串长度≥2时保留
        StructuralPrereq::RequiresSubstring(s) => {
            if s.len() >= 2 {
                vec![s]
            } else {
                vec![]
            }
        }
        // 任意子串要求：过滤掉长度<2的无效项
        StructuralPrereq::RequiresAny(v) => v.into_iter().filter(|s| s.len() >= 2).collect(),
        // 无前置条件：返回空列表
        StructuralPrereq::None => vec![],
    };

    // ========== 5. 核心分支逻辑：根据置信度和字面量有效性选择匹配门 ==========
    match (is_high_confidence, source_literal_len >= 2) {
        // 场景1：高置信度 → 优先使用token匹配（忽略字面量，依赖token的辨识度）
        (true, _) => MatchGate::with_tokens(tokens),

        // 场景2：低置信度 + 有效字面量（长度≥2）→ 字面量兜底 + 结构any匹配
        (false, true) => MatchGate::with_literal_and_any(source_literal, structural_any_list),

        // 场景3：低置信度 + 无效字面量 → 仅使用结构any匹配（最后的兜底策略）
        (false, false) => MatchGate::with_any(structural_any_list),
    }
}

/// 将最小证据元数据和结构前置条件折叠为匹配门（MatchGate）
/// 核心逻辑：基于token数量/密度、字面量有效性分级判定匹配策略，
/// 高置信度场景优先使用token匹配，低置信度场景降级为字面量/结构匹配
// 常量定义：匹配策略阈值（统一管理，便于后续调整）
/// Token数量阈值：判定"多token"的最小数量（≥3视为多token）
const TOKEN_COUNT_THRESHOLD: usize = 3;
/// Token总长度阈值：判定"token密集"的最小总长度（≥6视为密集）
const TOKEN_TOTAL_LEN_THRESHOLD: usize = 6;
/// 字符串最小有效长度：字面量/any项的最小有效长度（≥3视为有效）
const STR_MIN_VALID_LEN: usize = 3;

/// Any列表触发质量过滤的最小总数量：列表总长度≥此值才会进入质量筛选
const ANY_LIST_QUALITY_FILTER_MIN_TOTAL: usize = 3;
/// Any列表高质量项（长度>3）的最小数量：需至少有此数量的高质量项才执行过滤
const ANY_LIST_HIGH_QUALITY_ITEM_MIN_COUNT: usize = 2;
/// Any列表高质量项的最小长度阈值：长度>此值视为高质量项（区分3和>3）
const ANY_LIST_HIGH_QUALITY_ITEM_MIN_LEN: usize = 4;

pub fn fold_to_match_gate(
    min_evidence_meta: MinEvidenceMeta,
    structural_prereq: StructuralPrereq,
) -> MatchGate {
    // ========== 1. 解构元数据（减少重复访问，提升可读性） ==========
    let MinEvidenceMeta {
        tokens,         // 证据元数据中的token列表
        source_literal, // 源字面量（String类型，原始匹配文本）
        source_len,     // 源文本总长度（判定是否存在有效文本的基础）
        ..              // 忽略未使用的字段
    } = min_evidence_meta;

    // ========== 2. 核心判断条件计算（按需计算，避免冗余） ==========
    let token_len = tokens.len(); // Token列表长度
    let has_literal = source_len > 0; // 是否存在有效源文本（长度>0）
                                      // 源字面量有效性判断：非空且长度≥最小有效长度（String类型直接判断）
    let source_literal_is_valid: bool = source_literal.len() >= STR_MIN_VALID_LEN;

    // ========== 3. 高置信度判定逻辑（核心分级策略） ==========
    let has_many_tokens = token_len >= TOKEN_COUNT_THRESHOLD; // 是否为多token（≥3个）
                                                              // Token密集度判断：多token且总长度≥阈值（保证token具备足够辨识度）
    let tokens_dense = has_many_tokens
        && tokens.iter().map(|t| t.len()).sum::<usize>() >= TOKEN_TOTAL_LEN_THRESHOLD;
    // 是否需要验证字面量：存在有效文本但token数量≤1（token不足，需字面量兜底）
    let need_verify_literal = has_literal && token_len <= 1;
    // 高置信度判定：无需验证字面量，且满足"有有效文本"或"token密集"
    // 逻辑说明：高置信度场景下，token具备足够辨识度，可优先使用token匹配
    let is_high_confidence = !need_verify_literal && (has_literal || tokens_dense)
    ||
    //至少有一个token，并且字面量大于阈值6，视为高价值
    (token_len > 0 && source_len > TOKEN_TOTAL_LEN_THRESHOLD);

    // ========== 4. 预处理结构any列表（过滤无效项+去重） ==========
    let mut structural_any_list = match structural_prereq {
        // 单个子串要求：仅保留长度≥最小有效长度的项
        StructuralPrereq::RequiresSubstring(s) => {
            if s.len() >= STR_MIN_VALID_LEN {
                vec![s]
            } else {
                vec![]
            }
        }
        // 任意子串要求：过滤掉短于最小有效长度的无效项
        StructuralPrereq::RequiresAny(v) => v
            .into_iter()
            .filter(|s| s.len() >= STR_MIN_VALID_LEN)
            .collect(),
        // 无前置条件：返回空列表
        StructuralPrereq::None => vec![],
    };

    // any条件控制逻辑
    // 数量+质量双维度精细过滤（仅保留高质量项）
    // 1. 先计算关键指标
    let total_valid_items = structural_any_list.len(); // 有效项总数量
    let high_quality_item_count = structural_any_list
        .iter()
        .filter(|s| s.len() > ANY_LIST_HIGH_QUALITY_ITEM_MIN_LEN) // 统计长度>3的项
        .count();

    // 2. 判定是否满足过滤条件（数量达标 + 质量达标）
    let should_filter_by_quality = total_valid_items >= ANY_LIST_QUALITY_FILTER_MIN_TOTAL // 数量≥3
        && high_quality_item_count >= ANY_LIST_HIGH_QUALITY_ITEM_MIN_COUNT; // 高质量项≥2

    // 3. 执行过滤：仅保留长度>3的高质量项
    if should_filter_by_quality {
        structural_any_list.retain(|s| s.len() > ANY_LIST_HIGH_QUALITY_ITEM_MIN_LEN);
    }

    // ========== 5. 匹配门分支逻辑（基于置信度分级） ==========
    if is_high_confidence {
        // 场景1：高置信度 → 优先使用token匹配（依赖token的高辨识度）
        MatchGate::with_tokens(tokens)
    } else if source_literal_is_valid {
        // 场景2：低置信度+有效字面量 → 字面量兜底 + 结构any匹配
        MatchGate::with_literal_and_any(source_literal, structural_any_list)
    } else {
        // 场景3：低置信度+无效字面量 → 仅使用结构any匹配（最后兜底策略）
        MatchGate::with_any(structural_any_list)
    }
}
