use rswappalyzer_engine::{
    html_evidence::HtmlEvidence, scope_pruner::PruneScope, CompiledPattern, CompiledTechRule,
    RuleLibraryRuntime,
};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::{
    analyzer::{common::handle_match_success, Analyzer},
    VersionExtractor,
};

pub struct HtmlAnalyzer;

impl Analyzer<[CompiledPattern], HtmlEvidence<'_>> for HtmlAnalyzer {
    const TYPE_NAME: &'static str = "HTML";

    /// 获取 HTML 相关的规则模式
    fn get_patterns(tech: &CompiledTechRule) -> Option<&[CompiledPattern]> {
        tech.html_patterns.as_deref()
    }

    /// 实现通用 trait 定义的 match_logic，类型完全对齐
    fn match_logic(
        tech_name: &str,
        patterns: &[CompiledPattern],
        evidence: &HtmlEvidence,
        filtered_tokens: &FxHashSet<String>,
        literals_hit_lc: &FxHashSet<String>,
        any_hit_lc: &FxHashSet<String>,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        let input = evidence.html;

        for pattern in patterns {
            let matcher = pattern.exec.get_matcher();

            if pattern.matches_with_prune(input, filtered_tokens, literals_hit_lc, any_hit_lc) {
                let version = matcher.captures(evidence.html).and_then(|cap| {
                    VersionExtractor::extract(&pattern.exec.version_template, &cap)
                });
                handle_match_success(
                    Self::TYPE_NAME,
                    tech_name,
                    "HTML_CONTENT",
                    evidence.html,
                    &version,
                    Some(pattern.exec.confidence),
                    &matcher.describe(),
                    detected,
                );
            }
        }
    }
}

impl HtmlAnalyzer {
    /// HTML 分析器入口
    pub fn analyze(
        runtime_lib: &RuleLibraryRuntime,
        evidence: &HtmlEvidence,
        literals_hit_lc: &FxHashSet<String>,
        any_hit_lc: &FxHashSet<String>,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        <Self as Analyzer<[CompiledPattern], HtmlEvidence<'_>>>::analyze(
            runtime_lib,
            evidence,
            PruneScope::Html,
            literals_hit_lc,
            any_hit_lc,
            detected,
        );
    }
}