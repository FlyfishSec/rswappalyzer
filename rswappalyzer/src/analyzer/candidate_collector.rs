use rswappalyzer_engine::{CompiledRuleLibrary, scope_pruner::PruneScope};
use rustc_hash::FxHashSet;

/// 从反向索引筛选候选技术，核心性能函数，O(1)查找
/// 输入：规则库+令牌+当前解析维度 → 输出：去重的候选技术名称集合
// NOTE:
// Token-based FxHashSet lookup is O(N_tokens).
// Substring search on raw HTML is O(N_tokens * input_len) and is forbidden here.
pub fn collect_candidate_techs<'a>(
    compiled_lib: &'a CompiledRuleLibrary,
    input_tokens: &FxHashSet<String>,
    scope: PruneScope,
) -> FxHashSet<&'a String> {
    // 调试旁路：可指定任意要调试的技术名称
    // if scope == PruneScope::Header {
    //     debug_compiled_rule_library(compiled_lib, input_tokens, scope, "Apache Tomcat");
    // }

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

/// 通用化的规则库调试方法
/// 支持指定任意技术名称，输出该技术的全量调试信息及最终处置结果
/// 参数:
/// - compiled_lib: 编译后的规则库
/// - input_tokens: 解析出的输入令牌集合
/// - current_scope: 当前解析维度（如 Html/Header 等）
/// - target_tech_name: 要调试的目标技术名称（如 "Apache Tomcat"）
pub fn debug_compiled_rule_library(
    compiled_lib: &CompiledRuleLibrary,
    input_tokens: &FxHashSet<String>,
    current_scope: PruneScope,
    target_tech_name: &str,
) {
    // ========== 1. 基础全局统计信息 ==========
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

    // ========== 2. 当前维度全局统计 ==========
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

    // ========== 3. 令牌质量统计 ==========
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

    // 打印前8个特殊字符关键词样例
    if !special_char_keys.is_empty() {
        let sample_size = std::cmp::min(8, special_char_keys.len());
        let sample = &special_char_keys[0..sample_size];
        log::debug!(
            "[TOKEN-SAMPLE ❌] 含特殊字符关键词样例(前{}) = {:?}",
            sample_size, sample
        );
    }

    // ========== 4. 目标技术专属详细调试 ==========
    log::debug!("\n===== 【{}】专属调试信息 =====", target_tech_name);
    
    // 4.1 规则库中是否存在该技术
    let tech_rule = match compiled_lib.tech_patterns.get(target_tech_name) {
        Some(rule) => {
            log::debug!("[{}] 规则库状态：存在该技术的匹配规则", target_tech_name);
            rule
        }
        None => {
            log::debug!("[{}] 规则库状态：❌ 未找到该技术的匹配规则", target_tech_name);
            log::debug!("[{}] 最终处置结果：过滤（规则库无该技术）", target_tech_name);
            return; // 无规则直接退出
        }
    };

    // 4.2 该技术的Meta[generator]最小证据集
    let min_evidence = tech_rule
        .meta_patterns
        .as_ref()
        .and_then(|m| m.get("generator"))
        .and_then(|patterns| patterns.first())
        .and_then(|p| match &p.exec.match_gate {
            rswappalyzer_engine::MatchGate::RequireAll(set) => Some(set),
            _ => None,
        });
    log::debug!(
        "[{}] Meta[generator] 最小证据集 = {:?}",
        target_tech_name, min_evidence
    );

    // 4.3 是否在当前维度的无证据索引中
    let in_no_evidence = compiled_lib
        .no_evidence_index
        .get(&current_scope)
        .map_or(false, |techs| techs.contains(target_tech_name));
    log::debug!(
        "[{}] 当前维度({:?})无证据索引状态：{}",
        target_tech_name, current_scope, in_no_evidence
    );

    // 4.4 该技术关联的所有关键词（跨维度）
    let mut related_tokens = Vec::new();
    for (token, scope_map) in &compiled_lib.evidence_index {
        for (_scope, tech_names) in scope_map {
            if tech_names.contains(target_tech_name) {
                related_tokens.push(token.clone());
            }
        }
    }
    log::debug!(
        "[{}] 规则库中关联的所有关键词 = {:?}",
        target_tech_name, related_tokens
    );

    // 4.5 当前维度下该技术关联的关键词
    let mut current_scope_related_tokens = Vec::new();
    for (token, scope_map) in &compiled_lib.evidence_index {
        if let Some(tech_names) = scope_map.get(&current_scope) {
            if tech_names.contains(target_tech_name) {
                current_scope_related_tokens.push(token.clone());
            }
        }
    }
    log::debug!(
        "[{}] 当前维度({:?})下关联的关键词 = {:?}, 输入令牌 = {:?}",
        target_tech_name, current_scope, current_scope_related_tokens, &input_tokens
    );

    // 4.6 输入令牌中匹配到的该技术关键词
    let mut matched_tokens = Vec::new();
    for token in input_tokens {
        if let Some(scope_map) = compiled_lib.evidence_index.get(token.as_str()) {
            if let Some(tech_names) = scope_map.get(&current_scope) {
                if tech_names.contains(target_tech_name) {
                    matched_tokens.push(token.clone());
                }
            }
        }
    }
    log::debug!(
        "[{}] 输入令牌中匹配到的关键词 = {:?}",
        target_tech_name, matched_tokens
    );

    // ========== 5. 最终处置结果 ==========
    let is_allowed = !matched_tokens.is_empty();
    if is_allowed {
        log::info!("[{}] 最终处置结果：✅ 放行（已加入候选技术集合）", target_tech_name);
    } else {
        log::info!("[{}] 最终处置结果：❌ 过滤（未加入候选技术集合）", target_tech_name);
        // 补充过滤原因
        if current_scope_related_tokens.is_empty() {
            log::debug!("[{}] 过滤原因：当前维度({:?})下无该技术关联的关键词", target_tech_name, current_scope);
        } else {
            log::debug!("[{}] 过滤原因：输入令牌中无匹配该技术的关键词（需要的关键词：{:?}）", target_tech_name, current_scope_related_tokens);
        }
    }

    log::debug!("\n===== 【{}】调试结束 =====\n", target_tech_name);
}