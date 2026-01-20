

/// 候选技术集构建的详细统计信息
#[derive(Debug, Clone, Copy, Default)]
pub struct CandidateBuildStats {
    /// literal 匹配命中的技术数量（去重前）
    pub literal_hits: usize,
    /// any 匹配命中的技术数量（去重前）
    pub any_hits: usize,
    /// contains 匹配命中的技术数量（去重前）
    pub contains_hits: usize,
    /// 无证据技术的数量
    pub no_evidence_added: usize,
    /// 最终去重后的候选技术总数
    pub final_candidates: usize,
}

/// 构建候选技术集的返回结果
#[derive(Debug)]
pub struct CandidateBuildResult {
    pub techs: FxHashSet<TechId>,
    pub stats: CandidateBuildStats,
}

// 为 Result 实现快速转换
impl From<CandidateBuildResult> for FxHashSet<TechId> {
    fn from(result: CandidateBuildResult) -> Self {
        result.techs
    }
}
