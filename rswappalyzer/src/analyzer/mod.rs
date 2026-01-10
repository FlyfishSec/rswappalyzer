use std::time::Instant;

use log::debug;
use rswappalyzer_engine::{scope_pruner::PruneScope, CompiledRuleLibrary, CompiledTechRule};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::analyzer::candidate_collector::collect_candidate_techs;

pub mod candidate_collector;
pub mod common;
pub mod cookie;
pub mod header;
pub mod html;
pub mod meta;
pub mod script;
pub mod url;

/// 所有分析器的通用抽象特质
/// 核心：为泛型D添加 ?Sized 约束，兼容 str/[T] 等动态大小类型(DST)
/// 泛型约束：P-规则集类型，D-数据源类型(支持动态大小类型)
//pub trait Analyzer<P, D: ?Sized> {
pub trait Analyzer<P: ?Sized, D: ?Sized> {
    /// 分析器类型名称，用于日志标准化输出 (如URL/Header/Cookie)
    const TYPE_NAME: &'static str;

    /// 从编译后的技术规则中，获取当前分析器对应的规则集
    fn get_patterns(tech: &CompiledTechRule) -> Option<&P>;

    /// 核心业务匹配逻辑 - 所有分析器的唯一差异化实现点
    fn match_logic(
        tech_name: &str,
        patterns: &P,
        data: &D,
        input_tokens: &FxHashSet<String>,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    );

    /// 通用分析执行骨架 - 所有分析器共用，无差异化逻辑
    /// 封装：令牌提取 → 候选集构建 → 技术遍历 → 规则判空 → 调用业务匹配
    #[inline(always)]
    fn analyze(
        compiled_lib: &CompiledRuleLibrary,
        data: &D,
        token_iter: impl IntoIterator<Item = impl AsRef<str>>,
        scope: PruneScope, // 当前分析器绑定的维度
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) where
        Self: Sized,
    {
        let (candidate_tech_names, input_tokens) =
            build_candidate_techs(compiled_lib, token_iter, scope);

        // 遍历候选技术
        for tech_name in candidate_tech_names {
            let Some(tech) = compiled_lib.tech_patterns.get(tech_name) else {
                continue;
            };
            let Some(patterns) = Self::get_patterns(tech) else {
                continue;
            };

            Self::match_logic(&tech.name, patterns, data, &input_tokens, detected);
        }
    }
}

/// 通用令牌提取+候选集构建+无证据集技术合并公共方法
/// 入参：规则库、任意可迭代的字符串数据源
/// 出参：去重后的最终候选技术名称集合
/// 特性：泛型适配所有数据源类型
#[inline(always)]
fn build_candidate_techs<'a, I>(
    compiled_lib: &'a CompiledRuleLibrary,
    data_iter: I,
    scope: PruneScope, // 前解析器对应的维度
) -> (FxHashSet<&'a String>, FxHashSet<String>)
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    let mut tokens = FxHashSet::default();
    for data in data_iter {
        tokens
            .extend(crate::utils::extractor::token_extract_zh::extract_input_tokens(data.as_ref()));
    }

    // 1. 传入维度，筛选当前维度下的证据候选技术
    let mut candidate_techs =
        candidate_collector::collect_candidate_techs(compiled_lib, &tokens, scope);

    // 2. 适配维度化的无证据索引：只加载当前维度下的无证据技术
    if let Some(no_evidence_techs) = compiled_lib.no_evidence_index.get(&scope) {
        candidate_techs.extend(no_evidence_techs.iter());
    }

    (candidate_techs, tokens)
}

#[inline(always)]
#[allow(dead_code)]
fn build_candidate_techs_log<'a, I>(
    compiled_lib: &'a CompiledRuleLibrary,
    data_iter: I,
    scope: PruneScope,
) -> (FxHashSet<&'a String>, FxHashSet<String>)
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    // ========== 整体耗时起点 ==========
    let total_start = Instant::now();

    // ========== 1. Token提取阶段（重点统计） ==========
    let token_start = Instant::now();
    let mut tokens = FxHashSet::default();
    for data in data_iter {
        tokens
            .extend(crate::utils::extractor::token_extract_zh::extract_input_tokens(data.as_ref()));
    }
    // 计算Token提取耗时
    let token_duration = token_start.elapsed();
    // 打印Token生成耗时（两种方式选其一）
    // 方式1：用日志（推荐，可控制级别）
    debug!(
        "[{}维度] Token生成耗时: {}ms | 生成Token数量: {}",
        format!("{:?}", scope), // 打印维度（Header/Body/Url）
        token_duration.as_millis(),
        tokens.len()
    );
    // 方式2：直接打印到终端（调试用）
    // eprintln!(
    //     "[{}维度] Token生成耗时: {}ms | 生成Token数量: {}",
    //     format!("{:?}", scope),
    //     token_duration.as_millis(),
    //     tokens.len()
    // );

    // ========== 2. 候选技术收集阶段 ==========
    let candidate_start = Instant::now();
    let mut candidate_techs = collect_candidate_techs(compiled_lib, &tokens, scope);
    let candidate_duration = candidate_start.elapsed();

    // ========== 3. 无证据技术合并阶段 ==========
    let no_evidence_start = Instant::now();
    if let Some(no_evidence_techs) = compiled_lib.no_evidence_index.get(&scope) {
        candidate_techs.extend(no_evidence_techs.iter());
    }
    let no_evidence_duration = no_evidence_start.elapsed();

    // ========== 整体耗时统计 ==========
    let total_duration = total_start.elapsed();
    debug!(
        "[{}维度] 构建候选技术总耗时: {}ms | Token提取: {}ms | 候选收集: {}ms | 无证据合并: {}ms",
        format!("{:?}", scope),
        total_duration.as_millis(),
        token_duration.as_millis(),
        candidate_duration.as_millis(),
        no_evidence_duration.as_millis()
    );

    (candidate_techs, tokens)
}
