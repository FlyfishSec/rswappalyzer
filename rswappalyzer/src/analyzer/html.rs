//! HTML 内容分析器：基于 HTML 证据匹配技术检测规则

use rswappalyzer_engine::{
    CompiledPattern, CompiledTechRule, RuleLibraryRuntime, Scope, compiled::{LiteralInterner}, input_evidence::html_evidence::HtmlEvidence
};
use rustc_hash::{FxHashMap};

use crate::{
    analyzer::{
        common::{handle_match_success},
        Analyzer,
    },
    VersionExtractor,
};

/// HTML 内容分析器，实现通用分析器接口
pub struct HtmlAnalyzer;

impl Analyzer<[CompiledPattern], HtmlEvidence<'_>> for HtmlAnalyzer {
    /// 分析器类型标识
    const TYPE_NAME: &'static str = "HTML";

    /// 获取技术规则中的 HTML 匹配模式
    fn get_patterns(tech: &CompiledTechRule) -> Option<&[CompiledPattern]> {
        tech.html_patterns.as_deref()
    }

    /// HTML 模式匹配核心逻辑
    ///
    /// # 生命周期
    /// - `'d`: 绑定过滤后 Token 的引用生命周期
    ///
    /// # 参数
    /// - `tech_name`: 待检测技术名称
    /// - `patterns`: HTML 匹配模式集合
    /// - `evidence`: HTML 输入证据
    /// - `filtered_tokens`: 作用域过滤后的 Token 集合
    /// - `detected`: 检测结果（置信度, 版本）映射表
    fn match_logic<'d>(
        tech_name: &str,
        patterns: &[CompiledPattern],
        evidence: &HtmlEvidence<'_>,
        //filtered_token_ids: &FxHashSet<TokenId>,
        //token_interner: &'d TokenInterner,
        literal_interner: &'d LiteralInterner,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        // 零拷贝转换为 &str 集合
        //let (literals_hit_lc_str, any_hit_lc_str, contains_hit_lc_str) = evidence.get_all_str_sets();
        let (literals_hit_ids, any_hit_ids, contains_hit_ids) = (
            &evidence.literals_hit_ids,
            &evidence.any_hit_ids,
            &evidence.contains_hit_ids,
        );

        let input = evidence.html;

        for pattern in patterns {
            let matcher = pattern.exec.get_matcher();

            // 带作用域修剪的模式匹配
            if pattern.matches_with_prune(
                input,
                //filtered_token_ids,
                &literals_hit_ids,
                &any_hit_ids,
                &contains_hit_ids,
                //token_interner,
                literal_interner,
            ) {
                // 提取版本信息并更新检测结果
                let version = matcher.captures(evidence.html).and_then(|cap| {
                    VersionExtractor::extract(&pattern.exec.version_template, &cap)
                });

                handle_match_success(
                    Self::TYPE_NAME,
                    tech_name,
                    "HTML_CONTENT",
                    evidence.html,
                    &version,
                    Some(pattern.exec.confidence),
                    &matcher.describe(literal_interner),
                    detected,
                );
            }
        }
    }
}

impl HtmlAnalyzer {
    /// 启动 HTML 分析流程，指定 HTML 作用域执行检测
    ///
    /// # 参数
    /// - `runtime_lib`: 运行时规则库
    /// - `evidence`: HTML 输入证据
    /// - `detected`: 检测结果输出
    pub fn analyze(
        runtime_lib: &RuleLibraryRuntime,
        evidence: &HtmlEvidence<'_>,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        <Self as Analyzer<[CompiledPattern], HtmlEvidence<'_>>>::analyze(
            runtime_lib,
            evidence,
            Scope::Html,
            detected,
        );
    }
}
