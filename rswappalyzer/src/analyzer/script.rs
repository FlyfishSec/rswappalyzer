use rswappalyzer_engine::{
    html_evidence::HtmlEvidence, scope_pruner::PruneScope, CompiledPattern, CompiledTechRule,
    RuleLibraryRuntime,
};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::{
    analyzer::{common::handle_match_success, Analyzer},
    VersionExtractor,
};

/// Script 维度分析器（适配通用 Analyzer 骨架）
/// 核心能力：基于 script_src 匹配脚本相关技术规则
pub struct ScriptAnalyzer;

/// 实现通用 Analyzer 骨架，绑定 HtmlEvidence 作为数据载体
impl Analyzer<[CompiledPattern], HtmlEvidence<'_>> for ScriptAnalyzer {
    /// 分析器类型标识
    const TYPE_NAME: &'static str = "Script";

    /// 提取技术规则中的脚本模式集合
    /// 返回：脚本规则模式切片（Vec<CompiledPattern> → &[CompiledPattern]）
    fn get_patterns(tech: &CompiledTechRule) -> Option<&[CompiledPattern]> {
        tech.script_patterns.as_deref()
    }

    /// 脚本规则匹配核心逻辑
    /// 参数：
    /// - tech_name: 技术名称
    /// - patterns: 脚本规则模式集合
    /// - evidence: HTML 证据载体（包含 script_src/Token 等数据）
    /// - input_tokens: 预提取的 Token 集合（引用传递，零拷贝）
    /// - detected: 检测结果存储容器
    fn match_logic(
        tech_name: &str,
        patterns: &[CompiledPattern],
        evidence: &HtmlEvidence,
        input_tokens: &FxHashSet<String>,
        literals_hit_lc: &FxHashSet<String>,
        any_hit_lc: &FxHashSet<String>,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        // 从证据载体提取脚本核心数据（零拷贝）
        let input = evidence.script_src;

        // 遍历规则模式执行匹配
        for pattern in patterns {
            let matcher = pattern.exec.get_matcher();
            // 规则剪枝匹配
            if pattern.matches_with_prune(input, input_tokens, literals_hit_lc, any_hit_lc) {
                // 版本提取（基于规则模板和捕获组）
                let version = matcher.captures(input).and_then(|cap| {
                    VersionExtractor::extract(&pattern.exec.version_template, &cap)
                });

                // 匹配成功处理（更新检测结果 + 日志记录）
                handle_match_success(
                    Self::TYPE_NAME,
                    tech_name,
                    "SCRIPT_SRC",
                    input,
                    &version,
                    Some(pattern.exec.confidence),
                    &matcher.describe(),
                    detected,
                );
            }
        }
    }
}

impl ScriptAnalyzer {
    /// Script 分析器入口方法
    /// 参数：
    /// - runtime_lib: 运行时规则库
    /// - evidence: HTML 证据载体
    /// - detected: 检测结果输出容器
    #[inline(always)]
    pub fn analyze(
        runtime_lib: &RuleLibraryRuntime,
        evidence: &HtmlEvidence,
        literals_hit_lc: &FxHashSet<String>,
        any_hit_lc: &FxHashSet<String>,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        // 调用通用分析骨架（Script 维度剪枝）
        <Self as Analyzer<[CompiledPattern], HtmlEvidence<'_>>>::analyze(
            runtime_lib,
            evidence,
            PruneScope::Script,
            literals_hit_lc,
            any_hit_lc,
            detected,
        );
    }
}
