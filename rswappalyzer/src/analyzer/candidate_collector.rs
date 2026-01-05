use crate::{CompiledRuleLibrary, rule::indexer::index_pattern::MatchGate, utils::regex_filter::scope_pruner::PruneScope};
use rustc_hash::FxHashSet;

/// 从反向索引筛选候选技术，核心性能函数，O(1)查找
/// 输入：规则库+令牌+当前解析维度 → 输出：去重的候选技术名称集合
pub fn collect_candidate_techs<'a>(
    compiled_lib: &'a CompiledRuleLibrary,
    input_tokens: &FxHashSet<String>,
    scope: PruneScope, // 当前解析器对应的维度
) -> FxHashSet<&'a String> {
    // 调试旁路
    if scope == PruneScope::Cookie {
        debug_compiled_rule_library(compiled_lib, input_tokens, scope);
    }

    let mut candidates = FxHashSet::default();
    for token in input_tokens {
        if let Some(scope_to_techs) = compiled_lib.evidence_index.get(token.as_str()) {
            if let Some(tech_names) = scope_to_techs.get(&scope) {
                for tech_name in tech_names {
                    candidates.insert(tech_name);
                }
            }
        }
    }
    candidates
}

/// 调试方法
pub fn debug_compiled_rule_library(
    compiled_lib: &CompiledRuleLibrary,
    input_tokens: &FxHashSet<String>,
    current_scope: PruneScope,
) {
    // 基础统计
    log::debug!(
        "[RULE-LIB] 规则库总技术数 = {}",
        compiled_lib.tech_patterns.len()
    );
    log::debug!(
        "[EVIDENCE-INDEX] 维度化反向索引总关键词数 = {}",
        compiled_lib.evidence_index.len()
    );
    log::debug!(
        "[INPUT] 当前解析维度 = {:?} | 输入令牌数 = {}",
        current_scope,
        input_tokens.len()
    );

    // 统计当前解析维度下，反向索引能命中的「关键词+技术数」
    let mut current_scope_techs = FxHashSet::default();
    let mut current_scope_token_count = 0;
    for (_token, scope_map) in &compiled_lib.evidence_index {
        if scope_map.contains_key(&current_scope) {
            current_scope_token_count += 1;
            current_scope_techs.extend(scope_map.get(&current_scope).unwrap());
        }
    }
    log::debug!(
        "[SCOPE-STAT] 维度[{:?}]可命中关键词数 = {} | 维度[{:?}]关联技术数 = {}",
        current_scope,
        current_scope_token_count,
        current_scope,
        current_scope_techs.len()
    );

    // Token质量核心统计
    let is_clean_token = |s: &str| {
        s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    };
    let (clean_token_keys, special_char_keys): (Vec<_>, Vec<_>) = compiled_lib
        .evidence_index
        .keys()
        .partition(|k| is_clean_token(k));

    log::debug!(
        "[TOKEN-QUALITY] 纯字母关键词数 = {} ({:.2}%) | 含特殊字符关键词数 = {} ({:.2}%)",
        clean_token_keys.len(),
        clean_token_keys.len() as f64 / compiled_lib.evidence_index.len() as f64 * 100.0,
        special_char_keys.len(),
        special_char_keys.len() as f64 / compiled_lib.evidence_index.len() as f64 * 100.0
    );

    // 打印前20个特殊字符关键词样例
    if !special_char_keys.is_empty() {
        let sample = &special_char_keys[0..std::cmp::min(20, special_char_keys.len())];
        log::debug!(
            "[TOKEN-SAMPLE ❌] 含特殊字符关键词样例(前{}) = {:?}",
            sample.len(),
            sample
        );
    }

    // tech 调试
    const TARGET_TECH: &str = "Slimbox";
    match compiled_lib.tech_patterns.get(TARGET_TECH) {
        Some(rule) => {
            log::debug!("[WISYCMS] 技术规则存在于规则库中");
            let min_evidence = rule
                .meta_patterns
                .as_ref()
                .and_then(|m| m.get("generator"))
                .and_then(|patterns| patterns.first())
                .and_then(|p| match &p.exec.match_gate {
                    MatchGate::RequireAll(set) => Some(set),
                    _ => None,
                });
            log::debug!("[WISYCMS] Meta[generator] 最小证据集 = {:?}", min_evidence);
            // 额外补充：该技术是否在当前维度的无证据索引中
            let in_no_evidence = compiled_lib
                .no_evidence_index
                .get(&current_scope)
                .map_or(false, |techs| techs.contains(TARGET_TECH));
            log::debug!("[WISYCMS] 是否在当前维度无证据索引中 = {}", in_no_evidence);
        }
        None => log::debug!("[WISYCMS ❌] 技术规则未在规则库中找到！"),
    }
}
