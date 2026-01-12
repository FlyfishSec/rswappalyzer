use rswappalyzer_engine::{
    html_evidence::HtmlEvidence, scope_pruner::PruneScope, CompiledPattern, CompiledTechRule,
    RuleLibraryRuntime,
};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::{
    analyzer::{
        common::{handle_exists_success, handle_match_success},
        Analyzer,
    },
    VersionExtractor,
};

/// Meta 标签维度分析器（适配通用 Analyzer 骨架）
/// 核心能力：基于 Meta 标签匹配网页技术规则（支持存在性/正则双重匹配）
pub struct MetaAnalyzer;

/// 实现通用 Analyzer 骨架，绑定 HtmlEvidence 作为数据载体
impl Analyzer<FxHashMap<String, Vec<CompiledPattern>>, HtmlEvidence<'_>> for MetaAnalyzer {
    /// 分析器类型标识
    const TYPE_NAME: &'static str = "Meta";

    /// 提取技术规则中的 Meta 模式映射表
    /// 返回：Meta 规则模式映射（Key: Meta 标签名，Value: 规则模式列表）
    fn get_patterns(tech: &CompiledTechRule) -> Option<&FxHashMap<String, Vec<CompiledPattern>>> {
        tech.meta_patterns.as_ref()
    }

    /// Meta 规则匹配核心逻辑
    /// 支持两种匹配模式：
    /// 1. 存在性匹配：仅检查 Meta 标签是否存在
    /// 2. 正则/包含匹配：检查标签内容并提取版本
    /// 参数：
    /// - tech_name: 技术名称
    /// - meta_patterns: Meta 规则模式映射表
    /// - evidence: HTML 证据载体（包含 Meta 标签/Token 等数据）
    /// - input_tokens: 预提取的 Token 集合（引用传递，零拷贝）
    /// - detected: 检测结果存储容器
    fn match_logic(
        tech_name: &str,
        meta_patterns: &FxHashMap<String, Vec<CompiledPattern>>,
        evidence: &HtmlEvidence,
        input_tokens: &FxHashSet<String>,
        literals_hit_lc: &FxHashSet<String>,
        any_hit_lc: &FxHashSet<String>,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        // 从证据载体提取 Meta 标签映射（零拷贝复用）
        let meta_map = evidence
            .meta_tags
            .iter()
            .map(|(name, content)| (name.as_str(), content.as_str()))
            .collect::<FxHashMap<&str, &str>>();

        // 遍历 Meta 规则模式（按标签名分组）
        for (tag_name, patterns) in meta_patterns {
            // 判断是否为存在性匹配规则
            let has_exists_rule = patterns.iter().any(|p| p.exec.get_matcher().is_exists());

            // 分支1：存在性匹配（仅检查标签是否存在）
            if has_exists_rule && meta_map.contains_key(tag_name.as_str()) {
                let confidence = patterns
                    .iter()
                    .find(|p| p.exec.get_matcher().is_exists())
                    .map(|p| p.exec.confidence);
                handle_exists_success(Self::TYPE_NAME, tech_name, tag_name, confidence, detected);
            }
            // 分支2：正则/包含匹配（检查标签内容并提取版本）
            else if let Some(tag_content) = meta_map.get(tag_name.as_str()) {
                for pattern in patterns {
                    let matcher = pattern.exec.get_matcher();
                    // 非存在性规则 + 传递核心字段进行剪枝匹配
                    if !matcher.is_exists() {
                        let prune_pass = pattern.matches_with_prune(
                            tag_content,     // 当前Meta标签的内容（input）
                            input_tokens,     // Token集合（Meta维度复用HTML的Token）
                            literals_hit_lc, // AC literals预计算结果
                            any_hit_lc,      // AC any预计算结果
                        );

                        if prune_pass {
                            // 版本提取
                            let version = matcher.captures(tag_content).and_then(|cap| {
                                VersionExtractor::extract(&pattern.exec.version_template, &cap)
                            });
                            // 匹配成功处理
                            handle_match_success(
                                Self::TYPE_NAME,
                                tech_name,
                                tag_name,
                                tag_content,
                                &version,
                                Some(pattern.exec.confidence),
                                &matcher.describe(),
                                detected,
                            );
                            break; // 单标签匹配成功后终止遍历
                        }
                    }
                }
            }
        }
    }
}

impl MetaAnalyzer {
    /// Meta 分析器入口方法
    /// 参数：
    /// - runtime_lib: 运行时规则库
    /// - evidence: HTML 证据载体（包含 Meta 标签数据）
    /// - detected: 检测结果输出容器
    #[inline(always)]
    pub fn analyze(
        runtime_lib: &RuleLibraryRuntime,
        evidence: &HtmlEvidence,
        literals_hit_lc: &FxHashSet<String>,
        any_hit_lc: &FxHashSet<String>,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        // 调用通用分析骨架（Meta 维度剪枝）
        <Self as Analyzer<FxHashMap<String, Vec<CompiledPattern>>, HtmlEvidence<'_>>>::analyze(
            runtime_lib,
            evidence,
            PruneScope::Meta,
            literals_hit_lc,
            any_hit_lc,
            detected,
        );
    }
}
