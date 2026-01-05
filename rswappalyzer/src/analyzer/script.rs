use rustc_hash::{FxHashMap, FxHashSet};

use crate::{
    CompiledRuleLibrary, VersionExtractor, analyzer::{Analyzer, common::handle_match_success}, rule::indexer::index_pattern::{CompiledPattern, CompiledTechRule}, utils::regex_filter::scope_pruner::PruneScope
};

// Script 分析器
pub struct ScriptAnalyzer;
impl Analyzer<[CompiledPattern], str> for ScriptAnalyzer {
    const TYPE_NAME: &'static str = "Script";

    fn get_patterns(tech: &CompiledTechRule) -> Option<&[CompiledPattern]> {
        //tech.script_patterns.as_ref()
        tech.script_patterns.as_deref() // Vec<T> → &[T]
    }

    fn match_logic(
        tech_name: &str,
        patterns: &[CompiledPattern],
        script_src_combined: &str,
        script_tokens: &FxHashSet<String>,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        for pattern in patterns {
            let matcher = pattern.exec.matcher.to_matcher();
            if pattern.matches_with_prune(script_src_combined, script_tokens) {
                let version = matcher
                    .captures(script_src_combined)
                    .and_then(|cap| VersionExtractor::extract(&pattern.exec.version_template, &cap));
                handle_match_success(
                    Self::TYPE_NAME,
                    tech_name,
                    "SCRIPT_SRC",
                    script_src_combined,
                    &version,
                    Some(pattern.exec.confidence),
                    &matcher.describe(),
                    detected,
                );
            }
        }
    }
}

impl ScriptAnalyzer {
    pub fn analyze(
        compiled_lib: &CompiledRuleLibrary,
        script_src_combined: &str,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        <Self as Analyzer<_, _>>::analyze(
            compiled_lib,
            script_src_combined,
            std::iter::once(script_src_combined),
            PruneScope::Script,
            detected,
        );
    }
}
