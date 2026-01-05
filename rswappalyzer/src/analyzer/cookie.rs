use rustc_hash::{FxHashMap, FxHashSet};

use crate::{
    analyzer::{common::handle_match_success, Analyzer},
    rule::indexer::index_pattern::{CompiledPattern, CompiledTechRule},
    utils::regex_filter::scope_pruner::PruneScope,
    CompiledRuleLibrary, VersionExtractor,
};

// Cookie 分析器
pub struct CookieAnalyzer;

impl Analyzer<FxHashMap<String, Vec<CompiledPattern>>, FxHashMap<String, Vec<String>>>
    for CookieAnalyzer
{
    const TYPE_NAME: &'static str = "Cookie";

    fn get_patterns(tech: &CompiledTechRule) -> Option<&FxHashMap<String, Vec<CompiledPattern>>> {
        tech.cookie_patterns.as_ref()
    }

    fn match_logic(
        tech_name: &str,
        cookie_patterns: &FxHashMap<String, Vec<CompiledPattern>>,
        standard_cookies: &FxHashMap<String, Vec<String>>,
        cookie_tokens: &FxHashSet<String>,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        //log::debug!("standard_cookies: {:?}",&standard_cookies);
        for (rule_cookie_name, patterns) in cookie_patterns {
            let cookie_exists = standard_cookies.contains_key(rule_cookie_name);
            // if tech_name == "simploCMS" {
            //     log::debug!(
            //         "【终极实证】standard_cookies的真实KEY列表: {:?}",
            //         standard_cookies.keys().collect::<Vec<_>>()
            //     );
            //     log::debug!(
            //     "[COOKIE-匹配实时值] 技术名={}, 规则要求匹配的Cookie KEY={}, contains_key结果={}",
            //     tech_name,
            //     rule_cookie_name,
            //     cookie_exists
            // );
            // }

            if !cookie_exists {
                continue;
            }
            let cookie_values = standard_cookies.get(rule_cookie_name).unwrap();

            for cookie_val in cookie_values {
                let mut confidence: Option<u8> = None;
                let mut version: Option<String> = None;

                for pattern in patterns {
                    let matcher = pattern.exec.matcher.to_matcher();
                    if matcher.is_exists() {
                        // exists规则匹配成功：只要Cookie存在就命中
                        confidence = Some(pattern.exec.confidence);
                        break; // 无需匹配其他规则
                    } else if pattern.matches_with_prune_log(cookie_val, cookie_tokens) {
                        confidence = Some(pattern.exec.confidence);
                        version = matcher.captures(cookie_val).and_then(|cap| {
                            VersionExtractor::extract(&pattern.exec.version_template, &cap)
                        });
                        break; // 无需匹配其他规则
                    }
                }

                if confidence.is_some() {
                    handle_match_success(
                        Self::TYPE_NAME,
                        tech_name,
                        rule_cookie_name,
                        cookie_val,
                        &version,
                        confidence,
                        rule_cookie_name,
                        detected,
                    );
                    break;
                }
            }
        }
    }
}

impl CookieAnalyzer {
    pub fn analyze(
        compiled_lib: &CompiledRuleLibrary,
        cookies: &FxHashMap<String, Vec<String>>,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        let token_iter = cookies.values().flatten();
        <Self as Analyzer<_, _>>::analyze(
            compiled_lib,
            cookies,
            token_iter,
            PruneScope::Cookie,
            detected,
        );
    }
}
