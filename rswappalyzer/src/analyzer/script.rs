//! Script 标签分析器：基于脚本源地址匹配技术检测规则

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

/// Script 维度分析器，实现通用 Analyzer 接口
/// 核心能力：基于 script_src 匹配脚本相关技术规则
pub struct ScriptAnalyzer;

impl Analyzer<[CompiledPattern], HtmlEvidence<'_>> for ScriptAnalyzer {
    /// 分析器类型标识
    const TYPE_NAME: &'static str = "Script";

    /// 获取技术规则中的脚本模式集合
    fn get_patterns(tech: &CompiledTechRule) -> Option<&[CompiledPattern]> {
        tech.script_patterns.as_deref()
    }

    /// 脚本规则匹配核心逻辑
    /// 
    /// # 生命周期
    /// - `'d`: 绑定过滤后 Token 的引用生命周期
    /// 
    /// # 参数
    /// - `tech_name`: 待检测技术名称
    /// - `patterns`: 脚本规则模式集合
    /// - `evidence`: HTML 输入证据（包含 script_src 数据）
    /// - `filtered_tokens`: 作用域过滤后的 Token 集合（&String 类型）
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
        if evidence.script_src.is_empty() {
            return;
        }

        // 零拷贝转换为 &str 集合
        //let filtered_tokens_str = convert_string_ref_set_to_str_set(filtered_tokens);
        //let (literals_hit_lc_str, any_hit_lc_str, contains_hit_lc_str) = evidence.get_all_str_sets();
        let (literals_hit_ids, any_hit_ids, contains_hit_ids) = (
            &evidence.literals_hit_ids,
            &evidence.any_hit_ids,
            &evidence.contains_hit_ids,
        );

        // 提取脚本输入
        let input = evidence.script_src;

        // 遍历规则模式执行剪枝匹配
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
                // 基于捕获组提取版本信息
                let version = matcher
                    .captures(input)
                    .and_then(|cap| VersionExtractor::extract(&pattern.exec.version_template, &cap));
                
                // 更新检测结果
                handle_match_success(
                    Self::TYPE_NAME,
                    tech_name,
                    "SCRIPT_SRC",
                    input,
                    &version,
                    Some(pattern.exec.confidence),
                    &matcher.describe(literal_interner),
                    detected,
                );
            }
        }
    }

}

impl ScriptAnalyzer {
    /// 启动 Script 标签分析流程
    /// 
    /// # 参数
    /// - `runtime_lib`: 运行时规则库
    /// - `evidence`: HTML 输入证据
    /// - `detected`: 检测结果输出
    #[inline(always)]
    pub fn analyze(
        runtime_lib: &RuleLibraryRuntime,
        evidence: &HtmlEvidence<'_>,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        <Self as Analyzer<[CompiledPattern], HtmlEvidence<'_>>>::analyze(
            runtime_lib,
            evidence,
            Scope::Script,
            detected,
        );
    }
}