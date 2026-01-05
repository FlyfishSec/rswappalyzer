use std::borrow::Cow;

use rustc_hash::{FxHashMap, FxHashSet};

use crate::{
    analyzer::{common::handle_match_success, Analyzer},
    rule::indexer::index_pattern::{CompiledPattern, CompiledTechRule},
    utils::regex_filter::scope_pruner::PruneScope,
    CompiledRuleLibrary, VersionExtractor,
};

// HTML 分析器
pub struct HtmlAnalyzer;
//impl Analyzer<Vec<CompiledPattern>, str> for HtmlAnalyzer {
impl Analyzer<[CompiledPattern], str> for HtmlAnalyzer {
    const TYPE_NAME: &'static str = "HTML";

    //fn get_patterns(tech: &CompiledTechRule) -> Option<&Vec<CompiledPattern>> {
    fn get_patterns(tech: &CompiledTechRule) -> Option<&[CompiledPattern]> {
        //tech.html_patterns.as_ref()
        tech.html_patterns.as_deref() // Vec<T> → &[T]
    }

    fn match_logic(
        tech_name: &str,
        //patterns: &Vec<CompiledPattern>,
        patterns: &[CompiledPattern],
        html: &str,
        html_tokens: &FxHashSet<String>,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        for pattern in patterns {
            if tech_name == "Slimbox" {
                log::debug!(
                    "HTML内容: {}, Pattern内容: {}",
                    &html,
                    &pattern.exec.matcher.to_matcher().describe()
                );
            }
            let matcher = pattern.exec.matcher.to_matcher();
            if pattern.matches_with_prune_log(html, html_tokens) {
            //if pattern.matches(html) {
                let version = matcher
                    .captures(html)
                    .and_then(|cap| VersionExtractor::extract(&pattern.exec.version_template, &cap));
                handle_match_success(
                    Self::TYPE_NAME,
                    tech_name,
                    "HTML_CONTENT",
                    html,
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
    pub fn analyze(
        compiled_lib: &CompiledRuleLibrary,
        html: &Cow<str>,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        let html = html.as_ref();
        <Self as Analyzer<_, _>>::analyze(
            compiled_lib,
            html,
            std::iter::once(html),
            PruneScope::Html,
            detected,
        );
    }
}
