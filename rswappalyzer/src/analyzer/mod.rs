use aho_corasick::BuildError;
use log::debug;
use rswappalyzer_engine::{
    header_evidence::HeaderEvidence, html_evidence::HtmlEvidence, scope_pruner::PruneScope,
    CompiledTechRule, RuleLibraryRuntime,
};
use rustc_hash::{FxHashMap, FxHashSet};

mod candidate_collector;
pub mod common;
pub mod cookie;
pub mod header;
pub mod html;
pub mod meta;
pub mod script;
pub mod url;
// 导入候选集核心函数（过滤函数已在candidate_collector中定义）
use candidate_collector::{collect_candidate_techs, filter_tokens_by_scope};

/// 抽象接口：统一获取各类Evidence的提取Token
pub trait AnalyzerInput {
    fn get_extracted_tokens(&self) -> &FxHashSet<String>;
}

/// HtmlEvidence实现AnalyzerInput接口
impl<'a> AnalyzerInput for HtmlEvidence<'a> {
    fn get_extracted_tokens(&self) -> &FxHashSet<String> {
        &self.html_tokens
    }
}

/// HeaderEvidence实现AnalyzerInput接口
impl<'a> AnalyzerInput for HeaderEvidence<'a> {
    fn get_extracted_tokens(&self) -> &FxHashSet<String> {
        &self.header_tokens
    }
}

/// 通用分析器骨架：定义分析流程和匹配逻辑接口
pub trait Analyzer<P: ?Sized, D: AnalyzerInput> {
    /// 分析器类型名称（如HTML/Header）
    const TYPE_NAME: &'static str;

    /// 获取指定技术规则的匹配模式
    fn get_patterns(tech: &CompiledTechRule) -> Option<&P>;

    /// 具体匹配逻辑：由各分析器实现
    fn match_logic(
        tech_name: &str,
        patterns: &P,
        data: &D,
        filtered_tokens: &FxHashSet<String>,
        literals_hit_lc: &FxHashSet<String>,
        any_hit_lc: &FxHashSet<String>,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    );

    /// 通用分析流程：过滤Token→构建候选集→精准匹配
    #[inline(always)]
    fn analyze<'a>(
        runtime_lib: &'a RuleLibraryRuntime,
        data: &D,
        scope: PruneScope,
        literals_hit_lc: &FxHashSet<String>,
        any_hit_lc: &FxHashSet<String>,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) where
        Self: Sized,
    {
        // 1. 获取原始Token（通过统一接口）
        let original_tokens = data.get_extracted_tokens();

        // 2. 按Scope过滤Token（仅执行一次，无冗余）
        let filtered_tokens = filter_tokens_by_scope(
            original_tokens,
            runtime_lib.compiled_lib.known_tokens_by_scope.get(&scope),
        );

        // 3. 构建候选技术集（传递过滤后的Token，避免重复计算）
        let candidate_tech_names = match build_all_candidate_techs(runtime_lib, &filtered_tokens, scope) {
            Ok(res) => res,
            Err(e) => {
                debug!("构建候选技术集失败: {:?}", e);
                FxHashSet::default()
            }
        };

        // 4. 遍历候选技术，执行具体匹配逻辑
        for tech_name in candidate_tech_names {
            let Some(tech) = runtime_lib.compiled_lib.tech_patterns.get(tech_name) else {
                continue;
            };
            let Some(patterns) = Self::get_patterns(tech) else {
                continue;
            };

            Self::match_logic(
                &tech.name,
                patterns,
                data,
                &filtered_tokens,
                literals_hit_lc,
                any_hit_lc,
                detected,
            );
        }
    }
}

/// 构建候选技术集：封装核心函数调用，统一错误处理
#[inline(always)]
fn build_all_candidate_techs<'a>(
    runtime_lib: &'a RuleLibraryRuntime,
    filtered_tokens: &FxHashSet<String>,
    scope: PruneScope,
) -> Result<FxHashSet<&'a String>, BuildError> {
    let candidate_techs = collect_candidate_techs(
        &runtime_lib.compiled_lib,
        filtered_tokens,
        scope,
    );
    Ok(candidate_techs)
}