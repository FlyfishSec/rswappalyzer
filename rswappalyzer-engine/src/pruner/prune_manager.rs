//! 规则剪枝管理器模块
//! 核心能力：多阶段规则剪枝、耗时监控、调试日志，最大化匹配性能
//! 重构目标：全程基于ID对比，消除字符串操作

use log::{debug, warn};
use rustc_hash::FxHashSet;
use std::{fmt::Debug, sync::LazyLock, time::Instant};

use crate::{
    compiled::{LiteralId, LiteralInterner},
    pruner::scope_pruner,
    utils::log_format,
    MatchGate, Scope,
};

/// 剪枝执行模式
#[derive(Debug, Clone, Copy, Default)]
pub enum PruneMode {
    /// 纯执行模式（无日志，极致性能）
    #[default]
    Execute,
    /// 调试模式（输出阶段日志 + 耗时统计 + ID反向解析）
    Debug,
}

/// 剪枝上下文（仅保留必要的生命周期，移除多余泛型）
#[derive(Debug, Clone)]
pub struct PruneContext<'a> {
    /// 剪枝作用域（URL/HTML/Script等）
    pub scope: Scope,
    /// 待匹配输入字符串（仅用于日志预览）
    pub input: &'a str,
    // /// 输入内容的Token ID集合（核心对比用）
    // pub input_token_ids: &'a FxHashSet<TokenId>,
    /// 命中的字面量ID集合（核心对比用）
    pub literals_hit_ids: &'a FxHashSet<LiteralId>,
    /// 命中的Any字面量ID集合（核心对比用）
    pub any_hit_ids: &'a FxHashSet<LiteralId>,
    /// 命中的Contains字面量ID集合（预留）
    pub contains_hit_ids: &'a FxHashSet<LiteralId>,
    // /// Token字典（仅调试模式下反向解析ID用）
    // pub token_interner: &'a TokenInterner,
    /// 字面量字典（仅调试模式下反向解析ID用）
    pub literal_interner: &'a LiteralInterner,
    /// 全局黑名单索引Key
    pub index_key: &'a str,
    /// 匹配器描述（日志用）
    pub matcher_desc: &'a str,
    /// 剪枝执行模式
    pub mode: PruneMode,
    /// 耗时告警阈值（毫秒）
    pub time_threshold_ms: f64,
}

/// 剪枝管理器（核心剪枝逻辑内聚单元）
#[derive(Debug, Clone, Default)]
pub struct PruneManager;

impl PruneManager {
    /// 获取全局唯一实例（LazyLock 懒加载）
    pub fn global() -> &'static Self {
        static INSTANCE: LazyLock<PruneManager> = LazyLock::new(PruneManager::default);
        &INSTANCE
    }

    /// 核心剪枝入口（含整体耗时统计）
    #[inline(always)]
    pub fn prune<'a>(&self, gate: &MatchGate, ctx: &PruneContext<'a>) -> bool {
        // 记录剪枝开始时间
        let start = Instant::now();
        let result = self.inner_prune(gate, ctx);

        // 调试模式下输出超阈值耗时告警
        if matches!(ctx.mode, PruneMode::Debug) {
            let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
            if duration_ms > ctx.time_threshold_ms {
                warn!(
                    "[剪枝耗时告警] 整体剪枝 | Scope: {:?} | Rule: {} | 耗时: {:.1}ms | 结果: {}",
                    ctx.scope, ctx.matcher_desc, duration_ms, result
                );
            }
        }

        result
    }

    /// 内部剪枝逻辑（分离耗时统计与核心逻辑）
    #[inline(always)]
    fn inner_prune<'a>(&self, gate: &MatchGate, ctx: &PruneContext<'a>) -> bool {
        // 步骤1：全局黑名单剪枝（最高优先级）
        if !scope_pruner::struct_prune(ctx.scope, ctx.input, Some(ctx.index_key)) {
            self.log_blacklist_prune(ctx);
            return false;
        }

        // 步骤2：MatchGate多阶段剪枝（全程ID对比）
        self.prune_match_gate(gate, ctx)
    }

    /// 执行MatchGate多阶段剪枝（纯ID对比）
    #[inline(always)]
    fn prune_match_gate<'a>(&self, gate: &MatchGate, ctx: &PruneContext<'a>) -> bool {
        // 阶段1：必现字面量ID交集检查（复用Token的全包含逻辑）
        if let Some(require_literal_ids) = &gate.require_literal_ids {
            let pass = if matches!(ctx.mode, PruneMode::Debug) {
                let start = Instant::now();
                let pass = self.check_literal_stage_with_log(require_literal_ids, ctx);
                self.log_stage_duration(
                    "Stage1(Literal)",
                    ctx,
                    start.elapsed().as_secs_f64() * 1000.0,
                );
                pass
            } else {
                // 核心：全包含（交集）逻辑 - 所有必需的字面量ID都必须在命中集合中
                require_literal_ids
                    .iter()
                    .all(|&lid| ctx.literals_hit_ids.contains(&lid))
            };

            if !pass {
                return false;
            }
        }

        // 阶段2：Any字面量ID并集检查
        if let Some(require_any_literal_ids) = &gate.require_any_literal_ids {
            let pass = if matches!(ctx.mode, PruneMode::Debug) {
                let start = Instant::now();
                let pass = self.check_any_stage_with_log(require_any_literal_ids, ctx);
                self.log_stage_duration(
                    "Stage2(AnyLiteral)",
                    ctx,
                    start.elapsed().as_secs_f64() * 1000.0,
                );
                pass
            } else {
                // 核心：并集逻辑 - 至少有一个Any字面量ID在命中集合中
                require_any_literal_ids
                    .iter()
                    .any(|&lid| ctx.any_hit_ids.contains(&lid))
            };

            if !pass {
                return false;
            }
        }

        // 所有阶段通过
        self.log_all_stages_allowed(ctx);
        true
    }

    // ==================== 日志辅助方法（统一抽离） ====================
    /// 输出黑名单剪枝日志
    #[inline(always)]
    fn log_blacklist_prune<'a>(&self, ctx: &PruneContext<'a>) {
        if matches!(ctx.mode, PruneMode::Debug) {
            let input_preview = log_format::preview_compact(ctx.input, 120);
            debug!(
                "Blacklist prune filtered | Scope: {:?} | Input preview: {} | Length: {} | Rule: {}",
                ctx.scope,
                input_preview,
                ctx.input.len(),
                ctx.matcher_desc
            );
        }
    }

    /// 输出阶段耗时日志（超阈值时）
    #[inline(always)]
    fn log_stage_duration<'a>(&self, stage: &str, ctx: &PruneContext<'a>, duration_ms: f64) {
        if duration_ms > ctx.time_threshold_ms {
            debug!(
                "[剪枝阶段耗时] {} | Rule: {} | 耗时: {:.1}ms",
                stage, ctx.matcher_desc, duration_ms
            );
        }
    }

    /// 输出所有阶段通过的日志
    #[inline(always)]
    fn log_all_stages_allowed<'a>(&self, ctx: &PruneContext<'a>) {
        if matches!(ctx.mode, PruneMode::Debug) {
            let input_preview = log_format::preview_compact(ctx.input, 120);
            debug!(
                "All prune stages allowed | Input preview: {} | Rule: {}",
                input_preview, ctx.matcher_desc
            );
        }
    }

    // ==================== 带日志的检查方法（调试模式专用） ====================
    /// 字面量阶段剪枝（带日志，ID反向解析）
    #[inline(always)]
    fn check_literal_stage_with_log<'a>(
        &self,
        require_literal_ids: &[LiteralId],
        ctx: &PruneContext<'a>,
    ) -> bool {
        let input_preview = log_format::preview_compact(ctx.input, 120);

        // 空列表直接通过
        if require_literal_ids.is_empty() {
            debug!(
                "Stage1 (literal) prune allowed | Reason: Empty literal set (fallback allow) | Input preview: {} | Rule: {}",
                input_preview, ctx.matcher_desc
            );
            return true;
        }

        // 找出未命中的字面量ID（交集检查核心）
        let missing_literal_ids: Vec<LiteralId> = require_literal_ids
            .iter()
            .filter(|&&lid| !ctx.literals_hit_ids.contains(&lid))
            .cloned()
            .collect();

        if !missing_literal_ids.is_empty() {
            // 反向解析缺失的ID为字符串
            let missing_literals: Vec<String> = missing_literal_ids
                .iter()
                .map(|&lid| {
                    ctx.literal_interner
                        .get_literal(lid)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("<LiteralId:{:?}>", lid))
                })
                .collect();

            debug!(
                "Stage1 (literal) prune filtered | Input preview: {} | Missing literals: {:?} | Rule: {}",
                input_preview, missing_literals, ctx.matcher_desc
            );
            return false;
        }

        // 反向解析所有必需的字面量（日志输出）
        let require_literals: Vec<String> = require_literal_ids
            .iter()
            .map(|&lid| {
                ctx.literal_interner
                    .get_literal(lid)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("<LiteralId:{:?}>", lid))
            })
            .collect();

        debug!(
            "Stage1 (literal) prune allowed | Required literals: {:?} (IDs:{:?}) | Input preview: {} | Rule: {}",
            require_literals, require_literal_ids, input_preview, ctx.matcher_desc
        );

        true
    }

    /// Any字面量阶段剪枝（带日志）
    #[inline(always)]
    fn check_any_stage_with_log<'a>(
        &self,
        require_any_literal_ids: &[LiteralId],
        ctx: &PruneContext<'a>,
    ) -> bool {
        let input_preview = log_format::preview_compact(ctx.input, 120);

        // 空列表直接通过
        if require_any_literal_ids.is_empty() {
            debug!(
                "Stage2 (any literal) prune allowed | Reason: Empty any literal set (fallback allow) | Input preview: {} | Rule: {}",
                input_preview, ctx.matcher_desc
            );
            return true;
        }

        // 检查是否有至少一个Any字面量ID命中（并集逻辑）
        let hit_ids: Vec<LiteralId> = require_any_literal_ids
            .iter()
            .filter(|&&lid| ctx.any_hit_ids.contains(&lid))
            .cloned()
            .collect();

        if hit_ids.is_empty() {
            // 反向解析所有必需的Any字面量ID为字符串
            let require_any_strs: Vec<String> = require_any_literal_ids
                .iter()
                .map(|&lid| {
                    ctx.literal_interner
                        .get_literal(lid)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("<LiteralId:{:?}>", lid))
                })
                .collect();

            //if ctx.matcher_desc.contains("nginx"){println!("{:?}",ctx.literal_interner);}
            debug!(
                "Stage2 (any literal) prune filtered | Input preview: {} | Required any literals: {:?} | Rule: {}",
                input_preview, require_any_strs, ctx.matcher_desc
            );
            return false;
        }

        // 反向解析命中的ID
        let hit_strs: Vec<String> = hit_ids
            .iter()
            .map(|&lid| {
                ctx.literal_interner
                    .get_literal(lid)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("<LiteralId:{:?}>", lid))
            })
            .collect();

        debug!(
            "Stage2 (any literal) prune allowed | Hit any literals: {:?} (IDs:{:?}) | Input preview: {} | Rule: {}",
            hit_strs, hit_ids, input_preview, ctx.matcher_desc
        );

        true
    }
}
