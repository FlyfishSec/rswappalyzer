use rswappalyzer_engine::{CompiledPattern, CompiledRuleLibrary, CompiledTechRule, scope_pruner::PruneScope};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::{VersionExtractor, analyzer::{Analyzer, common::handle_match_success}};


// Header 分析器
pub struct HeaderAnalyzer;
impl Analyzer<FxHashMap<String, Vec<CompiledPattern>>, FxHashMap<String, String>> for HeaderAnalyzer {
    const TYPE_NAME: &'static str = "Header";

    fn get_patterns(tech: &CompiledTechRule) -> Option<&FxHashMap<String, Vec<CompiledPattern>>> {
        tech.header_patterns.as_ref()
    }

    fn match_logic(
        tech_name: &str,
        header_patterns: &FxHashMap<String, Vec<CompiledPattern>>,
        headers: &FxHashMap<String, String>,
        header_tokens: &FxHashSet<String>,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        for (name, patterns) in header_patterns {
            let header_val = headers.get(name);
            let mut matched = false;
            let mut confidence: Option<u8> = None;
            let mut version: Option<String> = None;
            let mut matched_rule = String::new();

            for pattern in patterns {
                let matcher = pattern.exec.get_matcher();
                if matcher.is_exists() {
                    if header_val.is_some() {
                        matched = true;
                        matched_rule = matcher.describe();
                        confidence = Some(pattern.exec.confidence);
                    }
                } else if let Some(val) = header_val {
                    if pattern.matches_with_prune(val, header_tokens) {
                        matched = true;
                        matched_rule = matcher.describe();
                        confidence = Some(pattern.exec.confidence);
                        version = matcher.captures(val).and_then(|cap| {
                            VersionExtractor::extract(&pattern.exec.version_template, &cap)
                        });
                        break;
                    }
                }
            }

            if matched {
                handle_match_success(
                    Self::TYPE_NAME,
                    tech_name,
                    name,
                    header_val.map(|v| v.as_str()).unwrap_or(""),
                    &version,
                    confidence,
                    &matched_rule,
                    detected
                );
            }
        }
    }
}

impl HeaderAnalyzer {
    pub fn analyze(
        compiled_lib: &CompiledRuleLibrary,
        headers: &FxHashMap<String, String>,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        <Self as Analyzer<_, _>>::analyze(compiled_lib, headers, headers.values(), PruneScope::Header, detected);
    }
}
