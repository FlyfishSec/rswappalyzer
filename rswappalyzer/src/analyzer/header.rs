//! HTTP 响应头分析器：基于 Header 信息匹配技术检测规则

use rswappalyzer_engine::{
    compiled::{LiteralInterner},
    input_evidence::header_evidence::HeaderEvidence,
    CompiledPattern, CompiledTechRule, RuleLibraryRuntime, Scope,
};
use rustc_hash::{FxHashMap};

use crate::{
    analyzer::{
        common::{handle_match_success},
        Analyzer,
    },
    VersionExtractor,
};

/// HTTP Header 维度分析器，实现通用 Analyzer 接口
/// 核心能力：基于 HTTP 响应头检测服务器/框架技术，支持存在性/正则匹配
pub struct HeaderAnalyzer;

impl Analyzer<FxHashMap<String, Vec<CompiledPattern>>, HeaderEvidence<'_>> for HeaderAnalyzer {
    /// 分析器类型标识
    const TYPE_NAME: &'static str = "Header";

    /// 获取技术规则中的 Header 模式映射表
    fn get_patterns(tech: &CompiledTechRule) -> Option<&FxHashMap<String, Vec<CompiledPattern>>> {
        tech.header_patterns.as_ref()
    }

    /// Header 规则匹配核心逻辑
    ///
    /// # 生命周期
    /// - `'d`: 绑定过滤后 Token 的引用生命周期
    ///
    /// # 参数
    /// - `tech_name`: 待检测技术名称
    /// - `header_patterns`: Header 规则模式映射表（头名称→模式列表）
    /// - `evidence`: Header 输入证据（包含响应头/Token 数据）
    /// - `filtered_tokens`: 作用域过滤后的 Token 集合（&String 类型）
    /// - `detected`: 检测结果（置信度, 版本）映射表
    fn match_logic<'d>(
        tech_name: &str,
        header_patterns: &FxHashMap<String, Vec<CompiledPattern>>,
        evidence: &HeaderEvidence<'_>,
        //filtered_token_ids: &FxHashSet<TokenId>,
        //token_interner: &'d TokenInterner,
        literal_interner: &'d LiteralInterner,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        // 零拷贝转换为 &str 集合
        //let filtered_tokens_str = convert_string_ref_set_to_str_set(filtered_tokens);
        let (literals_hit_ids, any_hit_ids, contains_hit_ids) = (
            &evidence.literals_hit_ids,
            &evidence.any_hit_ids,
            &evidence.contains_hit_ids,
        );

        // 提取响应头映射表
        let headers = &evidence.header_map;

        // 遍历 Header 规则模式（按响应头名称分组）
        for (header_name, patterns) in header_patterns {
            let header_val = headers.get(header_name);
            let mut matched = false;
            let mut confidence: Option<u8> = None;
            let mut version: Option<String> = None;
            let mut matched_rule = String::new();

            // 遍历当前 Header 对应的所有规则模式
            for pattern in patterns {
                let matcher = pattern.exec.get_matcher();

                // 分支1：存在性匹配（仅检查 Header 是否存在）
                if matcher.is_exists() {
                    if header_val.is_some() {
                        matched = true;
                        matched_rule = matcher.describe(literal_interner);
                        confidence = Some(pattern.exec.confidence);
                    }
                }
                // 分支2：正则/包含匹配（检查 Header 内容并提取版本）
                else if let Some(val) = header_val {
                    if pattern.matches_with_prune(
                        val,
                        //filtered_token_ids,
                        &literals_hit_ids,
                        &any_hit_ids,
                        &contains_hit_ids,
                        //token_interner,
                        literal_interner,
                    ) {
                        matched = true;
                        matched_rule = matcher.describe(literal_interner);
                        confidence = Some(pattern.exec.confidence);
                        // 基于捕获组提取版本信息
                        version = matcher.captures(val).and_then(|cap| {
                            VersionExtractor::extract(&pattern.exec.version_template, &cap)
                        });
                        break; // 单规则匹配成功后终止遍历
                    }
                }
            }

            // 匹配成功：更新检测结果
            if matched {
                handle_match_success(
                    Self::TYPE_NAME,
                    tech_name,
                    header_name,
                    header_val.map(|v| v.as_str()).unwrap_or(""),
                    &version,
                    confidence,
                    &matched_rule,
                    detected,
                );
            }
        }
    }
}

impl HeaderAnalyzer {
    /// 启动 HTTP Header 分析流程
    ///
    /// # 参数
    /// - `runtime_lib`: 运行时规则库
    /// - `evidence`: Header 输入证据
    /// - `detected`: 检测结果输出
    #[inline(always)]
    pub fn analyze(
        runtime_lib: &RuleLibraryRuntime,
        evidence: &HeaderEvidence<'_>,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        <Self as Analyzer<FxHashMap<String, Vec<CompiledPattern>>, HeaderEvidence<'_>>>::analyze(
            runtime_lib,
            evidence,
            Scope::Header,
            detected,
        );
    }
}
