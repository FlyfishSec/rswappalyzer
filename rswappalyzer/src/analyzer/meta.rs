//! Meta 标签分析器：基于 HTML 中的 Meta 标签匹配技术检测规则

use rswappalyzer_engine::{
    CompiledPattern, CompiledTechRule, RuleLibraryRuntime, Scope, compiled::{LiteralInterner}, input_evidence::html_evidence::HtmlEvidence
};
use rustc_hash::{FxHashMap};

use crate::{
    analyzer::{
        common::{handle_exists_success, handle_match_success},
        Analyzer,
    },
    VersionExtractor,
};

/// Meta 标签维度分析器，实现通用 Analyzer 接口
/// 核心能力：支持存在性匹配/正则匹配，基于 Meta 标签检测网页技术
pub struct MetaAnalyzer;

impl Analyzer<FxHashMap<String, Vec<CompiledPattern>>, HtmlEvidence<'_>> for MetaAnalyzer {
    /// 分析器类型标识
    const TYPE_NAME: &'static str = "Meta";

    /// 获取技术规则中的 Meta 模式映射表
    fn get_patterns(tech: &CompiledTechRule) -> Option<&FxHashMap<String, Vec<CompiledPattern>>> {
        tech.meta_patterns.as_ref()
    }

    /// Meta 规则匹配核心逻辑
    /// 
    /// # 生命周期
    /// - `'d`: 绑定过滤后 Token 的引用生命周期
    /// 
    /// # 参数
    /// - `tech_name`: 待检测技术名称
    /// - `meta_patterns`: Meta 规则模式映射表（标签名→模式列表）
    /// - `evidence`: HTML 输入证据（包含 Meta 标签数据）
    /// - `filtered_tokens`: 作用域过滤后的 Token 集合（&String 类型）
    /// - `detected`: 检测结果（置信度, 版本）映射表
    fn match_logic<'d>(
        tech_name: &str,
        meta_patterns: &FxHashMap<String, Vec<CompiledPattern>>,
        evidence: &HtmlEvidence<'_>,
        //filtered_token_ids: &FxHashSet<TokenId>,
        //token_interner: &'d TokenInterner,
        literal_interner: &'d LiteralInterner,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        // 零拷贝转换为 &str 集合
        let (literals_hit_ids, any_hit_ids, contains_hit_ids) = (
            &evidence.literals_hit_ids,
            &evidence.any_hit_ids,
            &evidence.contains_hit_ids,
        );

        // 修复：将 Meta 标签转换为 标签名→内容列表 的映射（保留所有同名标签）
        let mut meta_map: FxHashMap<&str, Vec<&str>> = FxHashMap::default();
        for (name, content) in evidence.meta_tags {
            // 按标签名分组，将内容添加到对应列表中
            meta_map.entry(name.as_str()).or_default().push(content.as_str());
        }

        // 遍历 Meta 规则模式（按标签名分组）
        for (tag_name, patterns) in meta_patterns {
            // 存在性匹配规则判断
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
            else if let Some(tag_contents) = meta_map.get(tag_name.as_str()) {
                // 修复：遍历当前标签名的所有内容值，而非仅单个值
                for tag_content in tag_contents {
                    for pattern in patterns {
                        let matcher = pattern.exec.get_matcher();
                        
                        // 非存在性规则执行剪枝匹配
                        if !matcher.is_exists() && pattern.matches_with_prune(
                            tag_content,
                            //filtered_token_ids,
                            &literals_hit_ids,
                            &any_hit_ids,
                            &contains_hit_ids,
                            //token_interner,
                            literal_interner,
                        ) {
                            // 版本提取
                            let version = matcher
                                .captures(tag_content)
                                .and_then(|cap| VersionExtractor::extract(&pattern.exec.version_template, &cap));
                            
                            // 更新检测结果
                            handle_match_success(
                                Self::TYPE_NAME,
                                tech_name,
                                tag_name,
                                tag_content,
                                &version,
                                Some(pattern.exec.confidence),
                                &matcher.describe(literal_interner),
                                detected,
                            );
                            break; // 单内容匹配成功后终止当前模式遍历
                        }
                    }
                }
            }
        }
    }
}

impl MetaAnalyzer {
    /// 启动 Meta 标签分析流程
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
        <Self as Analyzer<FxHashMap<String, Vec<CompiledPattern>>, HtmlEvidence<'_>>>::analyze(
            runtime_lib,
            evidence,
            Scope::Meta,
            detected,
        );
    }
}