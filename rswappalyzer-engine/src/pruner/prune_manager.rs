use std::sync::LazyLock;
use std::time::Instant;

use log::{debug, warn};
use rustc_hash::FxHashSet;

use crate::{
    pruner::{min_evidence_checker, scope_pruner},
    scope_pruner::PruneScope,
    utils::log_format,
    MatchGate,
};

static EMPTY_FX_HASH_SET: LazyLock<FxHashSet<String>> = LazyLock::new(FxHashSet::default);
//static EMPTY_STR_SET: LazyLock<FxHashSet<&str>> = LazyLock::new(FxHashSet::default);
static EMPTY_STRING_SET: LazyLock<FxHashSet<String>> = LazyLock::new(FxHashSet::default);

/// 剪枝配置（控制是否输出日志）
#[derive(Debug, Clone, Copy, Default)]
pub enum PruneMode {
    /// 纯执行模式（无日志，极致性能）
    #[default]
    Execute,
    /// 调试模式（输出阶段日志 + 耗时统计）
    Debug,
}

/// 剪枝上下文
#[derive(Debug, Clone)]
pub struct PruneContext<'a> {
    /// 剪枝作用域（URL/HTML/Script等）
    pub scope: PruneScope,
    /// 待匹配输入字符串
    pub input: &'a str,
    /// 输入令牌集合（用于最小证据校验）
    pub input_tokens: &'a FxHashSet<String>,
    // /// AC自动机预计算的literals命中结果
    // pub literals_hit: &'a FxHashSet<&'a str>,
    // /// AC自动机预计算的any命中结果
    // pub any_hit: &'a FxHashSet<&'a str>,
    // 规范化小写命中索引（contains专用）
    pub literals_hit_lc: &'a FxHashSet<String>,
    pub any_hit_lc: &'a FxHashSet<String>,
    /// 索引Key（全局黑名单剪枝用）
    pub index_key: &'a str,
    /// 匹配器描述（日志用）
    pub matcher_desc: &'a str,
    /// 剪枝模式（执行/调试）
    pub mode: PruneMode,
    /// 耗时阈值（毫秒）
    pub time_threshold_ms: f64,
}

// 为PruneContext添加默认值
impl<'a> Default for PruneContext<'a> {
    fn default() -> Self {
        Self {
            scope: PruneScope::Html,
            input: "",
            input_tokens: &EMPTY_FX_HASH_SET,
            literals_hit_lc: &EMPTY_STRING_SET,
            any_hit_lc: &EMPTY_STRING_SET,
            index_key: "",
            matcher_desc: "",
            mode: PruneMode::Execute,
            time_threshold_ms: 50.0,
        }
    }
}

/// 剪枝管理器（核心内聚单元）
#[derive(Debug, Clone, Default)]
pub struct PruneManager;

impl PruneManager {
    /// 全局唯一实例（延迟初始化）
    #[inline(always)]
    pub fn new() -> Self {
        Self
    }

    /// 核心剪枝方法（统一入口 + 整体耗时统计）
    #[inline(always)]
    pub fn prune(&self, gate: &MatchGate, ctx: &PruneContext) -> bool {
        // ========== 1. 记录整体剪枝开始时间 ==========
        let start = Instant::now();

        let result = self.inner_prune(gate, ctx);

        // ========== 2. 计算耗时并输出（仅Debug模式 + 超阈值） ==========
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

    /// 内部剪枝逻辑（分离耗时统计和核心逻辑）
    #[inline(always)]
    fn inner_prune(&self, gate: &MatchGate, ctx: &PruneContext) -> bool {
        // 步骤1：全局黑名单剪枝（最高优先级）
        if !scope_pruner::struct_prune(ctx.scope, ctx.input, Some(ctx.index_key)) {
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
            return false;
        }

        // 步骤2：MatchGate阶段剪枝
        self.prune_match_gate(gate, ctx)
    }

    /// 内部方法：执行MatchGate阶段剪枝（含日志/无日志逻辑 + 可选阶段耗时）
    #[inline(always)]
    fn prune_match_gate(&self, gate: &MatchGate, ctx: &PruneContext) -> bool {
        // 阶段1：Token交集检查（可选阶段耗时）
        if let Some(tokens) = &gate.require_tokens {
            let pass = if matches!(ctx.mode, PruneMode::Debug) {
                let start = Instant::now();
                let pass = self.check_token_stage_with_log(tokens, ctx);
                let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
                if duration_ms > ctx.time_threshold_ms {
                    debug!(
                        "[剪枝阶段耗时] Stage1(Token) | Rule: {} | 耗时: {:.1}ms | 结果: {}",
                        ctx.matcher_desc, duration_ms, pass
                    );
                }
                pass
            } else {
                tokens.iter().all(|t| ctx.input_tokens.contains(t))
            };
            if !pass {
                return false;
            }
        }

        // 阶段2：必现字面量检查（可选阶段耗时）
        if let Some(literal) = &gate.require_literal {
            let pass = if matches!(ctx.mode, PruneMode::Debug) {
                let start = Instant::now();
                let pass = self.check_literal_stage_with_log(literal, ctx);
                let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
                if duration_ms > ctx.time_threshold_ms {
                    debug!(
                        "[剪枝阶段耗时] Stage2(Literal) | Rule: {} | 耗时: {:.1}ms | 结果: {}",
                        ctx.matcher_desc, duration_ms, pass
                    );
                }
                pass
            } else {
                // let pass = ctx.literals_hit_lc.contains(literal); // 1. 计算bool值
                // if ctx.matcher_desc.contains("jquery-ui") {
                //     log::warn!(
                //         "microsoft-规则触发，literals_hit_lc: {:?}",
                //         ctx.literals_hit_lc
                //     );
                // }
                // pass
                ctx.literals_hit_lc.contains(literal)
                //contains_ignore_ascii_case(ctx.input, literal)
            };
            if !pass {
                return false;
            }
        }

        // 阶段3：Any字面量检查（可选阶段耗时）
        if let Some(any_list) = &gate.require_any_literal {
            let pass = if matches!(ctx.mode, PruneMode::Debug) {
                let start = Instant::now();
                let pass = self.check_any_stage_with_log(any_list, ctx);
                let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
                if duration_ms > ctx.time_threshold_ms {
                    debug!(
                        "[剪枝阶段耗时] Stage3(AnyLiteral) | Rule: {} | 耗时: {:.1}ms | 结果: {}",
                        ctx.matcher_desc, duration_ms, pass
                    );
                }
                pass
            } else {
                any_list.iter().any(|s| ctx.any_hit_lc.contains(s))
                // any_list
                //     .iter()
                //     .any(|s| contains_ignore_ascii_case(ctx.input, s))
            };
            if !pass {
                return false;
            }
        }

        // 所有阶段通过
        if matches!(ctx.mode, PruneMode::Debug) {
            let input_preview = log_format::preview_compact(ctx.input, 120);
            debug!(
                "All prune stages allowed | Input preview: {} | Rule: {}",
                input_preview, ctx.matcher_desc
            );
        }
        true
    }

    /// 内部方法：Token阶段（带日志）
    #[inline(always)]
    fn check_token_stage_with_log(&self, tokens: &FxHashSet<String>, ctx: &PruneContext) -> bool {
        let input_preview = log_format::preview_compact(ctx.input, 120);
        let input_tokens_preview = log_format::compress_token_set_default(ctx.input_tokens);

        let (pass_evidence, missing_evidence) =
            min_evidence_checker::check_min_evidence_prune_with_missing(tokens, ctx.input_tokens);

        if !pass_evidence {
            debug!(
                "Stage1 (token) prune filtered | Input preview: {} | Evidence set: {:?} | Missing evidence: {:?} | Input tokens: {:?} | Rule: {}",
                input_preview,
                tokens,
                missing_evidence,
                input_tokens_preview,
                ctx.matcher_desc
            );
            return false;
        }

        debug!(
            "Stage1 (token) prune allowed | Reason: {} | Input preview: {} | Evidence set: {:?} | Rule: {}",
            if tokens.is_empty() {
                "Empty evidence set (fallback allow)"
            } else {
                "Token intersection matched"
            },
            input_preview,
            tokens,
            ctx.matcher_desc
        );
        true
    }

    /// 内部方法：字面量阶段（带日志）
    #[inline(always)]
    fn check_literal_stage_with_log(&self, literal: &str, ctx: &PruneContext) -> bool {
        let input_preview = log_format::preview_compact(ctx.input, 120);
        // if ctx.matcher_desc.contains("jquery-ui") {
        //     log::warn!(
        //         "jquery-规则触发，literals_hit_lc: {:?}",
        //         ctx.literals_hit_lc
        //     );
        // }
        if !ctx.literals_hit_lc.contains(literal) {
            debug!(
                "Stage2 (literal) prune filtered | Input preview: {} | Required literal: {} | Rule: {}",
                input_preview,
                literal,
                ctx.matcher_desc
            );
            return false;
        }

        debug!(
            "Stage2 (literal) prune allowed | Required literal: {} | Input preview: {} | Rule: {}",
            literal, input_preview, ctx.matcher_desc
        );
        true
    }

    /// 内部方法：Any字面量阶段（带日志）
    #[inline(always)]
    fn check_any_stage_with_log(&self, any_list: &[String], ctx: &PruneContext) -> bool {
        let input_preview = log_format::preview_compact(ctx.input, 120);

        let hit = any_list.iter().any(|s| ctx.any_hit_lc.contains(s.as_str()));
        if !hit {
            debug!(
                "Stage3 (any literal) prune filtered | Input preview: {} | Required any: {:?} | Rule: {}",
                input_preview,
                any_list,
                ctx.matcher_desc
            );
            return false;
        }

        debug!(
            "Stage3 (any literal) prune allowed | Required any: {:?} | Input preview: {} | Rule: {}",
            any_list,
            input_preview,
            ctx.matcher_desc
        );
        true
    }
}

// 全局静态管理器
pub static GLOBAL_PRUNE_MANAGER: LazyLock<PruneManager> = LazyLock::new(|| PruneManager::new());
