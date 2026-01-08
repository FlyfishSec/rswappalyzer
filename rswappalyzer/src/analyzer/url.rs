use rswappalyzer_engine::{CompiledPattern, CompiledRuleLibrary, CompiledTechRule, scope_pruner::PruneScope};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::{VersionExtractor, analyzer::{Analyzer, common::handle_match_success}};

// URL 分析器
pub struct UrlAnalyzer;
impl Analyzer<[CompiledPattern], [&str]> for UrlAnalyzer {
    const TYPE_NAME: &'static str = "URL";

    fn get_patterns(tech: &CompiledTechRule) -> Option<&[CompiledPattern]> {
        tech.url_patterns.as_deref()
    }

    fn match_logic(
        tech_name: &str,
        patterns: &[CompiledPattern],
        urls: &[&str],
        url_tokens: &FxHashSet<String>,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        for url in urls {
            for pattern in patterns {
                let matcher = pattern.exec.get_matcher();
                if pattern.matches_with_prune(url, url_tokens) {
                    let version = matcher
                        .captures(url)
                        .and_then(|cap| VersionExtractor::extract(&pattern.exec.version_template, &cap));
                    handle_match_success(
                        Self::TYPE_NAME,
                        tech_name,
                        url,
                        url,
                        &version,
                        Some(pattern.exec.confidence),
                        &matcher.describe(),
                        detected,
                    );
                    break;
                }
            }
        }
    }
}

impl UrlAnalyzer {
    pub fn analyze(
        compiled_lib: &CompiledRuleLibrary,
        urls: &[&str],
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        <Self as Analyzer<_, _>>::analyze(compiled_lib, urls, urls, PruneScope::Url, detected);
    }
}
