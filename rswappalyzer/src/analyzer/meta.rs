use rswappalyzer_engine::{CompiledPattern, CompiledRuleLibrary, CompiledTechRule, scope_pruner::PruneScope};
use rustc_hash::{FxBuildHasher, FxHashMap, FxHashSet};

use crate::{VersionExtractor, analyzer::{Analyzer, common::{handle_exists_success, handle_match_success}}};

// Meta 分析器
pub struct MetaAnalyzer;
impl Analyzer<FxHashMap<String, Vec<CompiledPattern>>, FxHashMap<String, &str>> for MetaAnalyzer {
    const TYPE_NAME: &'static str = "Meta";

    fn get_patterns(tech: &CompiledTechRule) -> Option<&FxHashMap<String, Vec<CompiledPattern>>> {
        tech.meta_patterns.as_ref()
    }

    fn match_logic(
        tech_name: &str,
        meta_patterns: &FxHashMap<String, Vec<CompiledPattern>>,
        meta_map: &FxHashMap<String, &str>,
        meta_tokens: &FxHashSet<String>,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        for (name, patterns) in meta_patterns {
            // if name == "wisyCMS" {
            //     dbg!(&meta_map);
            // } else {
            //     dbg!(&name);
            // }

            let has_exists = patterns.iter().any(|p| p.exec.get_matcher().is_exists());

            // 存在性匹配分支 - 独立处理，无冗余赋值
            if has_exists && meta_map.contains_key(name) {
                let confidence = patterns
                    .iter()
                    .find(|p| p.exec.get_matcher().is_exists())
                    .map(|p| p.exec.confidence);
                handle_exists_success(Self::TYPE_NAME, tech_name, name, confidence, detected);
            }
            // 正则/包含匹配分支 - 按需声明变量，无提前赋值
            else if let Some(content) = meta_map.get(name) {
                for pattern in patterns {
                    let matcher = pattern.exec.get_matcher();
                    if !matcher.is_exists() && pattern.matches_with_prune(content, meta_tokens) {
                        let confidence = Some(pattern.exec.confidence);
                        let version = matcher.captures(content).and_then(|cap| {
                            VersionExtractor::extract(&pattern.exec.version_template, &cap)
                        });
                        handle_match_success(
                            Self::TYPE_NAME,
                            tech_name,
                            name,
                            content,
                            &version,
                            confidence,
                            &matcher.describe(),
                            detected,
                        );
                        break;
                    }
                }
            }
        }
    }
}

impl MetaAnalyzer {
    pub fn analyze(
        compiled_lib: &CompiledRuleLibrary,
        meta_tags: &[(String, String)],
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        let mut meta_map: FxHashMap<String, &str> =
            FxHashMap::with_capacity_and_hasher(meta_tags.len(), FxBuildHasher::default());
        for (name, content) in meta_tags {
            meta_map.insert(name.clone(), content.as_str());
        }
        let token_iter = meta_tags.iter().map(|(_, c)| c.as_str());
        <Self as Analyzer<_, _>>::analyze(compiled_lib, &meta_map, token_iter, PruneScope::Meta, detected);
    }
}
