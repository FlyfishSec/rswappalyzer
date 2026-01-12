use crate::{
    indexer::{enums::MatchGate, MatcherSpec},
    prune_manager::{self, PruneContext, PruneMode},
    scope_pruner::PruneScope,
    Matcher,
};
use once_cell::sync::OnceCell;
use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};

/// 可执行匹配模式（核心执行单元）
/// 职责：封装「如何匹配」的完整逻辑，包含匹配执行体、准入网关、权重和版本模板
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutablePattern {
    /// 匹配器静态描述（用于序列化）
    pub matcher: MatcherSpec,
    /// 懒加载的Matcher缓存（运行时使用，不序列化）
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
    /// 懒加载获取Matcher实例（OnceCell确保只初始化一次）
    #[inline(always)]
    pub fn get_matcher(&self) -> &Matcher {
        self.matcher_cache.get_or_init(|| self.matcher.to_matcher())
    }
}

/// 编译后的匹配模式（调度路由单元）
/// 职责：封装调度作用域、索引Key和可执行匹配核心，实现高性能匹配调度
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledPattern {
    /// 剪枝作用域（URL/HTML/Script等）
    pub scope: PruneScope,
    /// 索引Key（用于快速查找）
    #[serde(default)]
    pub index_key: String,
    /// 可执行匹配核心
    pub exec: ExecutablePattern,
}

impl CompiledPattern {
    /// 执行匹配（自动激活懒加载Matcher）
    /// 参数：input - 待匹配的字符串
    /// 返回：匹配结果（bool）
    #[inline(always)]
    pub fn matches(&self, input: &str) -> bool {
        self.exec.get_matcher().matches(input)
    }

    /// 纯执行模式剪枝（无日志）
    #[inline(always)]
    pub fn prune_check(
        &self,
        input: &str,
        input_tokens: &FxHashSet<String>,
        literals_hit_lc: &FxHashSet<String>,
        any_hit_lc: &FxHashSet<String>,
    ) -> bool {
        let ctx = PruneContext {
            scope: self.scope,
            input,
            input_tokens,
            literals_hit_lc,
            any_hit_lc,
            index_key: &self.index_key,
            matcher_desc: &self.exec.get_matcher().describe(),
            mode: PruneMode::Execute,
            time_threshold_ms: 50.0,
        };
        //if ctx.matcher_desc.contains("microsoft-")&& ctx.scope == PruneScope::Header {println!("{:?}",literals_hit_lc);}
        prune_manager::GLOBAL_PRUNE_MANAGER.prune(&self.exec.match_gate, &ctx)
    }

    /// 调试模式剪枝（带日志）
    #[inline(always)]
    pub fn prune_check_with_log(
        &self,
        input: &str,
        input_tokens: &FxHashSet<String>,
        literals_hit_lc: &FxHashSet<String>,
        any_hit_lc: &FxHashSet<String>,
    ) -> bool {
        let ctx = PruneContext {
            scope: self.scope,
            input,
            input_tokens,
            literals_hit_lc,
            any_hit_lc,
            index_key: &self.index_key,
            matcher_desc: &self.exec.get_matcher().describe(),
            mode: PruneMode::Debug,
            time_threshold_ms: 10.0,
        };
        prune_manager::GLOBAL_PRUNE_MANAGER.prune(&self.exec.match_gate, &ctx)
    }

    /// 剪枝 + 匹配
    #[inline(always)]
    pub fn matches_with_prune(
        &self,
        input: &str,
        input_tokens: &FxHashSet<String>,
        literals_hit_lc: &FxHashSet<String>,
        any_hit_lc: &FxHashSet<String>,
    ) -> bool {
        self.prune_check(input, input_tokens, literals_hit_lc, any_hit_lc) && self.matches(input)
    }

    /// 剪枝 + 匹配（调试模式）
    #[inline(always)]
    pub fn matches_with_prune_log(
        &self,
        input: &str,
        input_tokens: &FxHashSet<String>,
        literals_hit_lc: &FxHashSet<String>,
        any_hit_lc: &FxHashSet<String>
    ) -> bool {
        self.prune_check_with_log(input, input_tokens, literals_hit_lc, any_hit_lc) 
            && self.matches(input)
    }
}

/// 编译后技术规则（完整技术匹配规则）
/// 职责：封装单个技术的所有匹配模式，按作用域分类存储
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledTechRule {
    /// 技术名称
    pub name: String,
    /// URL匹配模式列表（可选）
    pub url_patterns: Option<Vec<CompiledPattern>>,
    /// HTML匹配模式列表（可选）
    pub html_patterns: Option<Vec<CompiledPattern>>,
    /// Script匹配模式列表（可选）
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
