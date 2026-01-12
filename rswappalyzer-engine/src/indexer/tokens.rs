use std::fmt;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::scope_pruner::PruneScope;

// 统计结果最小证据token结构体
/// Token频率统计结果
#[derive(Debug, Clone)]
pub struct TokenFrequencyStats {
    /// 全局Token频率（token -> 出现次数）
    pub global: FxHashMap<String, usize>,
    /// 按作用域划分的Token频率（scope -> token -> 出现次数）
    pub by_scope: FxHashMap<PruneScope, FxHashMap<String, usize>>,
}

impl fmt::Display for TokenFrequencyStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 1. 打印全局Top 10
        writeln!(f, "\n==================== 全局Token频率 Top 10 ====================")?;
        let mut global_sorted: Vec<(&String, &usize)> = self.global.iter().collect();
        global_sorted.sort_by(|a, b| b.1.cmp(a.1));
        for (i, (token, count)) in global_sorted.iter().take(10).enumerate() {
            writeln!(f, "{:2}. Token: {:<30} 出现次数: {}", i + 1, token, count)?;
        }

        // 2. 打印各作用域Top 10
        for (scope, scope_freq) in &self.by_scope {
            writeln!(f, "\n==================== {:?} 作用域Token频率 Top 10 ====================", scope)?;
            let mut scope_sorted: Vec<(&String, &usize)> = scope_freq.iter().collect();
            scope_sorted.sort_by(|a, b| b.1.cmp(a.1));
            for (i, (token, count)) in scope_sorted.iter().take(10).enumerate() {
                writeln!(f, "{:2}. Token: {:<30} 出现次数: {}", i + 1, token, count)?;
            }
        }

        Ok(())
    }
}


    /// 计算Token频率（全局 + 按作用域）
    /// 参数：evidence_index - 证据索引（token -> scope -> techs）
    /// 返回：Token频率统计结果
    pub fn calculate_token_frequency(
        evidence_index: &FxHashMap<String, FxHashMap<PruneScope, FxHashSet<String>>>,
    ) -> TokenFrequencyStats {
        let mut global_freq = FxHashMap::default();
        let mut by_scope_freq = FxHashMap::default();

        // 遍历每个token的证据索引
        for (token, scope_map) in evidence_index {
            // 统计全局频率：累加该token在所有作用域下关联的技术总数
            let global_count = scope_map
                .values()
                .map(|techs| techs.len())
                .sum::<usize>();
            *global_freq.entry(token.clone()).or_insert(0) += global_count;

            // 统计各作用域频率：按作用域分别累加
            for (scope, techs) in scope_map {
                let scope_entry: &mut FxHashMap<String, usize> = by_scope_freq.entry(*scope).or_default();                *scope_entry.entry(token.clone()).or_insert(0) += techs.len();
            }
        }

        TokenFrequencyStats {
            global: global_freq,
            by_scope: by_scope_freq,
        }
    }
