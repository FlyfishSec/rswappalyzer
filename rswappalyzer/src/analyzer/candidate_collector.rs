use aho_corasick::BuildError;
use rswappalyzer_engine::{
    CompiledRuleLibrary, RuleLibraryRuntime, Scope, compiled::{LiteralId, TechId}
};
use rustc_hash::FxHashSet;

/// 构建候选技术集
#[inline(always)]
pub fn build_all_candidate_techs<'a>(
    runtime_lib: &'a RuleLibraryRuntime,
    //filtered_token_ids: &FxHashSet<TokenId>,
    literal_hit_ids: &FxHashSet<LiteralId>,
    any_hit_ids: &FxHashSet<LiteralId>,
    contains_hit_ids: &FxHashSet<LiteralId>,
    scope: Scope,
) -> Result<FxHashSet<TechId>, BuildError> {
    let candidate_techs = 
        // 使用AC自动机的LiteralId构建候选
        collect_candidate_techs_by_literal(
            &runtime_lib.compiled_bundle.library,
            literal_hit_ids,
            any_hit_ids,
            contains_hit_ids,
            scope,
        );

    Ok(candidate_techs)
}

// 基于LiteralId构建候选技术集
#[inline(always)]
pub fn collect_candidate_techs_by_literal<'a>(
    compiled_lib: &'a CompiledRuleLibrary,
    literal_hit_ids: &FxHashSet<LiteralId>,
    any_hit_ids: &FxHashSet<LiteralId>,
    contains_hit_ids: &FxHashSet<LiteralId>,
    scope: Scope,
) -> FxHashSet<TechId> {
    let mut candidates = FxHashSet::default();

    // 1. 处理literal匹配的LiteralId
    for &literal_id in literal_hit_ids {
        let tech_ids = compiled_lib
            .literal_index
            .get(&literal_id)
            .and_then(|s| s.get(&scope));
        if let Some(techs) = tech_ids {
            candidates.extend(techs.iter());
        }
    }

    // 2. 处理any匹配的LiteralId
    for &literal_id in any_hit_ids {
        let tech_ids = compiled_lib
            .any_index
            .get(&literal_id)
            .and_then(|s| s.get(&scope));
        if let Some(techs) = tech_ids {
            candidates.extend(techs.iter());
        }
    }

    // 3. 处理contains匹配的LiteralId
    for &literal_id in contains_hit_ids {
        let tech_ids = compiled_lib
            .contains_index 
            .get(&literal_id)
            .and_then(|s| s.get(&scope));
        if let Some(techs) = tech_ids {
            candidates.extend(techs.iter());
        }
    }

    // 4. 合并无证据技术Id
    if let Some(no_evidence_techs) = compiled_lib.no_evidence_index.get(&scope) {
        candidates.extend(no_evidence_techs.iter());
    }

    candidates
}

// /// 基于过滤后的 Token 构建候选技术集（适配ID化）
// #[inline(always)]
// pub fn collect_candidate_techs_by_token<'a>(
//     compiled_lib: &'a CompiledRuleLibrary,
//     filtered_token_ids: &FxHashSet<TokenId>,
//     scope: Scope,
// ) -> FxHashSet<TechId> {
//     let mut candidates = FxHashSet::default();

//     // 遍历TokenId查询关联技术Id
//     for &token_id in filtered_token_ids {
//         let tech_ids = compiled_lib
//             .evidence_index
//             .get(&token_id)
//             .and_then(|s| s.get(&scope));
//         if let Some(techs) = tech_ids {
//             candidates.extend(techs.iter());
//         }
//     }

//     // 合并无证据技术Id
//     if let Some(no_evidence_techs) = compiled_lib.no_evidence_index.get(&scope) {
//         candidates.extend(no_evidence_techs.iter());
//     }

//     candidates
// }

// Scope到Pattern检查函数的映射
// pub fn get_scope_pattern_checker(scope: Scope) -> impl Fn(&CompiledTechRule) -> bool {
//     match scope {
//         Scope::Url => |tech: &CompiledTechRule| {
//             tech.url_patterns.as_ref().map_or(false, |pats| {
//                 pats.iter()
//                     .any(|pat| pat.evidence_kind != EvidenceKind::TokenBased)
//             })
//         },
//         Scope::Html => |tech: &CompiledTechRule| {
//             tech.html_patterns.as_ref().map_or(false, |pats| {
//                 pats.iter()
//                     .any(|pat| pat.evidence_kind != EvidenceKind::TokenBased)
//             })
//         },
//         Scope::Script => |tech: &CompiledTechRule| {
//             tech.script_patterns.as_ref().map_or(false, |pats| {
//                 pats.iter()
//                     .any(|pat| pat.evidence_kind != EvidenceKind::TokenBased)
//             })
//         },
//         Scope::Meta => |tech: &CompiledTechRule| {
//             tech.meta_patterns.as_ref().map_or(false, |pats| {
//                 pats.values()
//                     .flatten()
//                     .any(|pat| pat.evidence_kind != EvidenceKind::TokenBased)
//             })
//         },
//         Scope::Header => |tech: &CompiledTechRule| {
//             tech.header_patterns.as_ref().map_or(false, |pats| {
//                 pats.values()
//                     .flatten()
//                     .any(|pat| pat.evidence_kind != EvidenceKind::TokenBased)
//             })
//         },
//         Scope::Cookie => |tech: &CompiledTechRule| {
//             tech.cookie_patterns.as_ref().map_or(false, |pats| {
//                 pats.values()
//                     .flatten()
//                     .any(|pat| pat.evidence_kind != EvidenceKind::TokenBased)
//             })
//         },
//         // 其他Scope直接返回false
//         // _ => |_: &CompiledTechRule| false,
//     }
// }
