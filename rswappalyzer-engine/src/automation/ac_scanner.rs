//! AC自动机扫描工具模块
//!
//! 提供基于Aho-Corasick算法的高效字符串匹配能力，适配ID化的模式存储方案，
//! 支持HTML/Header维度的模式分类匹配，核心优化点：
//! 1. 存储LiteralId而非原始字符串，减少内存拷贝
//! 2. 延迟字符串转换，提升扫描性能

use crate::compiled::LiteralId;
use crate::pattern_kind::PatternKind;
use crate::{automation::cache::AcAutomatonCache, compiled::CompiledBundle};
use aho_corasick::{AhoCorasick, PatternID};
use log::warn;
use rustc_hash::FxHashSet;

/// AC自动机通用扫描工具：适配ID化后的AC缓存
///
/// 核心职责：
/// - 执行AC自动机匹配，输出LiteralId而非原始字符串
/// - 按PatternKind分类匹配结果
/// - 容错处理无效ID映射，保证扫描流程稳定性
#[derive(Debug, Clone, Copy)]
pub struct AcScanner;

impl AcScanner {
    /// 适配ID化的通用扫描+分类函数
    ///
    /// # 参数
    /// - `s`: 待扫描的原始字符串
    /// - `ac_combined`: 预编译的AC自动机实例
    /// - `ac_cache`: AC自动机缓存（存储PatternID/LiteralId/PatternKind映射）
    /// - `is_html`: 维度标识（true=HTML维度，false=Header维度）
    /// - `literals_hit`: Literal类型匹配结果（LiteralId集合）
    /// - `any_hit`: Any类型匹配结果（LiteralId集合）
    /// - `contains_hit`: Contains类型匹配结果（LiteralId集合）
    /// - `_bundle`: 预留的CompiledBundle引用（未来扩展用）
    ///
    /// # 安全保证
    /// 遇到无效ID映射时仅记录警告日志，跳过无效项，不触发panic
    // ⚠️ CRITICAL HOT PATH ⚠️
    // This function is on the AC scan hot path.
    // DO NOT add any extra logic, allocations, HashSet gates, logging, or branching here.
    // Any additional work must be done OUTSIDE this function.
    // Violating this WILL cause O(n) HTML scans to explode in runtime.
    #[inline(always)]
    pub fn scan_and_classify_with_id(
        s: &str,
        ac_combined: &AhoCorasick,
        ac_cache: &AcAutomatonCache,
        is_html: bool,
        literals_hit: &mut FxHashSet<LiteralId>,
        any_hit: &mut FxHashSet<LiteralId>,
        contains_hit: &mut FxHashSet<LiteralId>,
        _bundle: &CompiledBundle,
    ) {
        // 预分配容量（基于AC匹配结果的预估，更精准）
        let estimated_hits = s.len() / 100;
        literals_hit.reserve(estimated_hits);
        any_hit.reserve(estimated_hits);
        contains_hit.reserve(estimated_hits);

        // 直接遍历+插入，无中间Vec
        //ac_combined.find_iter(s).for_each(|mat| {
        ac_combined.find_overlapping_iter(s).for_each(|mat| {
            let pattern_id = mat.pattern();
            let Some((lit_id, kinds)) = Self::get_lit_id_and_kinds(pattern_id, ac_cache, is_html)
            else {
                return;
            };

            // 直接分类插入，无二次遍历
            kinds.iter().for_each(|&kind| match kind {
                PatternKind::Literal => {
                    literals_hit.insert(lit_id);
                }
                PatternKind::Any => {
                    any_hit.insert(lit_id);
                }
                PatternKind::Contains => {
                    contains_hit.insert(lit_id);
                }
            });
        });
    }

    /// 安全获取LiteralId和PatternKind
    #[inline(always)]
    fn get_lit_id_and_kinds(
        pattern_id: PatternID,
        ac_cache: &AcAutomatonCache,
        is_html: bool,
    ) -> Option<(LiteralId, &FxHashSet<PatternKind>)> {
        let lit_id = if is_html {
            ac_cache.html_pattern_id_to_literal_id(pattern_id)
        } else {
            ac_cache.header_pattern_id_to_literal_id(pattern_id)
        }?;

        let kinds = if is_html {
            ac_cache.html_get_pattern_kinds(lit_id)
        } else {
            ac_cache.header_get_pattern_kinds(lit_id)
        }?;

        Some((lit_id, kinds))
    }

    // /// 批量插入匹配结果（优化集合操作性能）
    // #[inline(always)]
    // fn batch_insert_hits(
    //     hit_pairs: &[(LiteralId, PatternKind)],
    //     literals_hit: &mut FxHashSet<LiteralId>,
    //     any_hit: &mut FxHashSet<LiteralId>,
    //     contains_hit: &mut FxHashSet<LiteralId>,
    // ) {
    //     // 预分配容量（仅扩容一次，性能优化）
    //     let total = hit_pairs.len();
    //     literals_hit.reserve(total);
    //     any_hit.reserve(total);
    //     contains_hit.reserve(total);

    //     // 无分支预测优化的批量插入（编译器可优化为跳转表）
    //     hit_pairs.iter().for_each(|&(lit_id, kind)| match kind {
    //         PatternKind::Literal => {
    //             literals_hit.insert(lit_id);
    //         }
    //         PatternKind::Any => {
    //             any_hit.insert(lit_id);
    //         }
    //         PatternKind::Contains => {
    //             contains_hit.insert(lit_id);
    //         }
    //     });
    // }

    /// 按PatternKind分类存储LiteralId
    ///
    /// 内部辅助函数，仅在扫描流程中调用，内联优化提升性能
    #[inline(always)]
    #[allow(dead_code)]
    fn classify_hit_id(
        kind: &PatternKind,
        lit_id: LiteralId,
        literals_hit: &mut FxHashSet<LiteralId>,
        any_hit: &mut FxHashSet<LiteralId>,
        contains_hit: &mut FxHashSet<LiteralId>,
    ) {
        match kind {
            PatternKind::Literal => {
                literals_hit.insert(lit_id);
            }
            PatternKind::Any => {
                any_hit.insert(lit_id);
            }
            PatternKind::Contains => {
                contains_hit.insert(lit_id);
            }
        }
    }

    /// 批量将LiteralId转换为字符串（延迟转换，非扫描时执行）
    ///
    /// # 参数
    /// - `ids`: 待转换的LiteralId集合
    /// - `bundle`: 包含LiteralId→字符串映射的CompiledBundle
    ///
    /// # 返回值
    /// 转换后的字符串集合（过滤空字符串，保证数据有效性）
    ///
    /// # 安全保证
    /// 无效LiteralId会记录警告日志，返回空字符串并过滤，不触发panic
    #[inline(always)]
    pub fn convert_ids_to_strings(
        ids: &FxHashSet<LiteralId>,
        bundle: &crate::compiled::CompiledBundle,
    ) -> FxHashSet<String> {
        ids.iter()
            .map(|&id| {
                bundle.get_literal(id)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| {
                        warn!(
                            "[AcScanner] Failed to convert LiteralId {:?} to string: Literal not found",
                            id
                        );
                        String::default()
                    })
            })
            .filter(|s| !s.is_empty()) // 过滤无效空字符串
            .collect()
    }
}
