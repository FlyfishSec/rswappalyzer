//! 编译后匹配规则模块
//! 核心能力：封装编译后的匹配模式、技术规则，提供高性能的剪枝+匹配执行能力

use once_cell::sync::OnceCell;
use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};
use std::fmt::Debug; // 1. 导入Debug trait

use crate::{
    EvidenceKind, Matcher, compiled::{LiteralId, LiteralInterner}, indexer::{
        MatcherSpec, enums::{MatchGate, Scope}
    }, prune_manager::{self, PruneContext, PruneMode}
};

/// 可执行匹配模式（核心执行单元）
/// 封装匹配逻辑、准入网关、置信度和版本提取模板，支持懒加载匹配器
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutablePattern {
    /// 匹配器静态描述（序列化用）
    pub matcher: MatcherSpec,
    /// 懒加载匹配器缓存（运行时使用，不序列化）
    #[serde(skip)]
    #[serde(default)]
    pub matcher_cache: OnceCell<Matcher>,

    /// 匹配准入网关（剪枝规则）
    #[serde(default)]
    pub match_gate: MatchGate,
    /// 匹配置信度（0-100）
    pub confidence: u8,
    /// 版本提取模板（可选）
    pub version_template: Option<String>,
}

impl ExecutablePattern {
    /// 懒加载获取匹配器实例（OnceCell 确保仅初始化一次）
    #[inline(always)]
    pub fn get_matcher(&self) -> &Matcher {
        self.matcher_cache.get_or_init(|| self.matcher.to_matcher())
    }
}

// /// 字面量类型枚举（用于映射池前缀标记）
// #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
// pub enum LiteralType {
//     Literal,    // 必现字面量
//     Contains,   // 必现子串
//     AnyLiteral, // 任意前置
// }

/// 构建期单Pattern的字面量证据（结构化分字段，读取高效）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PatternEvidence {
    /// 必现字面量（LiteralIndex用）
    pub literals: Vec<String>,
    /// Contains类型（ContainsIndex用）
    pub contains: String,
    /// 任意前置字面量（AnyLiteralIndex用）
    pub any_literals: Vec<String>,
}

/// 编译后的匹配模式（调度路由单元）
/// 封装调度作用域、索引Key和可执行匹配核心，实现高性能匹配调度
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledPattern {
    /// 剪枝作用域（URL/HTML/Script等）
    pub scope: Scope,
    /// 索引Key（快速查找用）
    #[serde(default)]
    pub index_key: String,
    /// 存储 Contains 类型的 LiteralId
    pub literal_id: Option<LiteralId>,
    /// 规则证据类型（TokenBased/ExistsOnly/PureRegex）
    pub evidence_kind: EvidenceKind,
    /// 构建期字面量证据（中间态，落地后可丢弃）
    #[serde(skip)]
    pub evidence: PatternEvidence,
    /// 可执行匹配核心
    pub exec: ExecutablePattern,
}

impl CompiledPattern {
    /// 执行字符串匹配（自动激活懒加载匹配器）
    ///
    /// # 参数
    /// - `input`: 待匹配字符串
    /// - `contains_hit_lc`: 小写包含命中集合
    ///
    /// # 返回值
    /// 匹配结果（bool）
    #[inline(always)]
    pub fn matches(&self, input: &str, contains_hit_ids: &FxHashSet<LiteralId>) -> bool {
        //pub fn matches<T: Eq + Hash + Borrow<str> + Debug>(&self, input: &str, contains_hit_lc: &FxHashSet<T>) -> bool {
        // 短路调试
        // false
        self.exec.get_matcher().matches(input, contains_hit_ids)
    }

    /// 纯执行模式剪枝检查
    #[inline(always)]
    pub fn prune_check(
        &self,
        input: &str,
        //input_token_ids: &FxHashSet<TokenId>,
        literals_hit_ids: &FxHashSet<LiteralId>,
        any_hit_ids: &FxHashSet<LiteralId>,
        contains_hit_ids: &FxHashSet<LiteralId>,
        //token_interner: &TokenInterner,
        literal_interner: &LiteralInterner,
    ) -> bool {
        let ctx = PruneContext {
            scope: self.scope,
            input,
            //input_token_ids,
            literals_hit_ids,
            any_hit_ids,
            contains_hit_ids,
            //token_interner,
            literal_interner,
            index_key: &self.index_key,
            matcher_desc: &self.exec.get_matcher().describe(literal_interner),
            mode: PruneMode::Execute,
            time_threshold_ms: 50.0,
        };
        prune_manager::PruneManager::global().prune(&self.exec.match_gate, &ctx)
    }

    /// 调试模式剪枝检查（带日志 + 耗时统计）
    #[inline(always)]
    //pub fn prune_check_with_log<T: Eq + Hash + Borrow<str> + Debug>(
    pub fn prune_check_with_log(
        &self,
        input: &str,
        //input_token_ids: &FxHashSet<TokenId>,
        literals_hit_ids: &FxHashSet<LiteralId>,
        any_hit_ids: &FxHashSet<LiteralId>,
        contains_hit_ids: &FxHashSet<LiteralId>,
        //token_interner: &TokenInterner,
        literal_interner: &LiteralInterner,
    ) -> bool {
        let ctx = PruneContext {
            scope: self.scope,
            input,
            //input_token_ids,
            literals_hit_ids,
            any_hit_ids,
            contains_hit_ids,
            //token_interner,
            literal_interner,
            index_key: &self.index_key,
            matcher_desc: &self.exec.get_matcher().describe(literal_interner),
            mode: PruneMode::Debug,
            time_threshold_ms: 10.0,
        };
        prune_manager::PruneManager::global().prune(&self.exec.match_gate, &ctx)
    }

    /// 剪枝 + 匹配（纯执行模式）
    #[inline(always)]
    pub fn matches_with_prune(
        &self,
        input: &str,
        //input_token_ids: &FxHashSet<TokenId>,
        literals_hit_ids: &FxHashSet<LiteralId>,
        any_hit_ids: &FxHashSet<LiteralId>,
        contains_hit_ids: &FxHashSet<LiteralId>,
        //token_interner: &TokenInterner,
        literal_interner: &LiteralInterner,
    ) -> bool {
        //false
        self.prune_check(
            input,
            //input_token_ids,
            literals_hit_ids,
            any_hit_ids,
            contains_hit_ids,
            //token_interner,
            literal_interner,
        ) && self.matches(input, contains_hit_ids)
    }

    /// 剪枝 + 匹配（调试模式）
    #[inline(always)]
    pub fn matches_with_prune_log(
        &self,
        input: &str,
        //input_token_ids: &FxHashSet<TokenId>,
        literals_hit_ids: &FxHashSet<LiteralId>,
        any_hit_ids: &FxHashSet<LiteralId>,
        contains_hit_ids: &FxHashSet<LiteralId>,
        //token_interner: &TokenInterner,
        literal_interner: &LiteralInterner,
    ) -> bool {
        // 短路调试
        // false
        self.prune_check_with_log(
            input,
            //input_token_ids,
            literals_hit_ids,
            any_hit_ids,
            contains_hit_ids,
            //token_interner,
            literal_interner,
        ) && self.matches(input, contains_hit_ids)
    }
}

/// 编译后技术规则（完整技术匹配规则）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledTechRule {
    /// 技术名称
    pub name: String,
    /// URL匹配模式列表
    pub url_patterns: Option<Vec<CompiledPattern>>,
    /// HTML匹配模式列表
    pub html_patterns: Option<Vec<CompiledPattern>>,
    /// Script匹配模式列表
    pub script_patterns: Option<Vec<CompiledPattern>>,
    /// Meta匹配模式映射（Key=Meta名称，Value=匹配模式列表）
    pub meta_patterns: Option<FxHashMap<String, Vec<CompiledPattern>>>,
    /// Header匹配模式映射（Key=Header名称，Value=匹配模式列表）
    pub header_patterns: Option<FxHashMap<String, Vec<CompiledPattern>>>,
    /// Cookie匹配模式映射（Key=Cookie名称，Value=匹配模式列表）
    pub cookie_patterns: Option<FxHashMap<String, Vec<CompiledPattern>>>,
    /// 所属分类ID列表
    pub category_ids: Vec<u32>,
    /// 推导技术列表（匹配该技术后可推导的其他技术）
    pub implies: Vec<String>,
}
