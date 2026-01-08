//! 正则过滤 - 最小证据剪枝模块
//! 提供语义安全的最小证据提取、输入令牌提取、剪枝校验能力
use rustc_hash::FxHashSet;

/// 最小证据剪枝入口
#[inline(always)]
pub fn check_min_evidence_prune(
    evidence_set: &FxHashSet<String>,
    input_tokens: &FxHashSet<String>
) -> bool {
    if evidence_set.is_empty() {
        return true;
    }
    // 直接用透传的token校验，零提取、零计算开销
    evidence_set.iter().all(|e| input_tokens.contains(e.as_str()))
}

/// 最小证据剪枝入口
#[inline(always)]
pub fn check_min_evidence_prune_with_missing(
    evidence_set: &FxHashSet<String>,
    input_tokens: &FxHashSet<String>
) -> (bool, Vec<String>) {
    if evidence_set.is_empty() {
        return (true, Vec::new());
    }
    let missing_evidence: Vec<_> = evidence_set.iter()
        .filter(|e| !input_tokens.contains(e.as_str()))
        .cloned()
        .collect();
    (missing_evidence.is_empty(), missing_evidence)
}
