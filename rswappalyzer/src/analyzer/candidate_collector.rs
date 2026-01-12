use rswappalyzer_engine::{CompiledRuleLibrary, scope_pruner::PruneScope};
use rustc_hash::FxHashSet;

/// 按Scope过滤Token：输出String集合，匹配底层方法类型要求
#[inline(always)]
pub fn filter_tokens_by_scope(
    input_tokens: &FxHashSet<String>,
    scope_known_tokens: Option<&FxHashSet<String>>,
) -> FxHashSet<String> {
    match scope_known_tokens {
        Some(known) => input_tokens
            .intersection(known)
            .cloned() // 短字符串克隆，性能影响可忽略
            .collect(),
        None => FxHashSet::default(),
    }
}

/// 基于过滤后的Token构建候选技术集
#[inline(always)]
pub fn collect_candidate_techs<'a>(
    compiled_lib: &'a CompiledRuleLibrary,
    filtered_tokens: &FxHashSet<String>,
    scope: PruneScope,
) -> FxHashSet<&'a String> {
    let mut candidates = FxHashSet::default();

    // 遍历过滤后的Token，查询反向索引获取候选技术
    for token in filtered_tokens {
        if let Some(scope_to_techs) = compiled_lib.evidence_index.get(token.as_str()) {
            if let Some(tech_names) = scope_to_techs.get(&scope) {
                candidates.extend(tech_names.iter());
            }
        }
    }

    // 合并无证据技术规则
    if let Some(no_evidence_techs) = compiled_lib.no_evidence_index.get(&scope) {
        candidates.extend(no_evidence_techs.iter());
    }

    candidates
}