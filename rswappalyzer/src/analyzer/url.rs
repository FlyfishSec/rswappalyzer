//! URL 分析器：基于 URL 地址匹配技术检测规则

use rswappalyzer_engine::{
    CompiledPattern,
    CompiledTechRule,
    RuleLibraryRuntime,
    Scope,
    compiled::{LiteralId, LiteralInterner},
};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::{
    analyzer::{
        common::handle_match_success,
        Analyzer,
    },
    VersionExtractor,
};
use crate::analyzer::AnalyzerInput;

/// URL 维度分析器，实现通用 Analyzer 接口
/// 核心能力：基于 URL 地址匹配技术规则，支持版本提取
pub struct UrlAnalyzer;

impl<'a> Analyzer<[CompiledPattern], UrlEvidence<'a>> for UrlAnalyzer {
    /// 分析器类型标识
    const TYPE_NAME: &'static str = "URL";

    /// 获取技术规则中的 URL 模式集合
    fn get_patterns(tech: &CompiledTechRule) -> Option<&[CompiledPattern]> {
        tech.url_patterns.as_deref()
    }

    /// URL 规则匹配核心逻辑（适配 ID 化 + interner 透传）
    /// 
    /// # 生命周期
    /// - `'d`: 绑定过滤后 Token 的引用生命周期
    /// 
    /// # 参数
    /// - `tech_name`: 待检测技术名称
    /// - `patterns`: URL 匹配模式集合
    /// - `evidence`: URL 输入证据
    /// - `filtered_token_ids`: 作用域过滤后的 TokenId 集合
    /// - `token_interner`: Token 映射池（用于 ID ↔ 字符串转换）
    /// - `literal_interner`: Literal 映射池（用于 ID ↔ 字符串转换）
    /// - `detected`: 检测结果（置信度, 版本）映射表
    fn match_logic<'d>(
        tech_name: &str,
        patterns: &[CompiledPattern],
        evidence: &UrlEvidence<'a>,
        //filtered_token_ids: &FxHashSet<TokenId>,
        //token_interner: &'d TokenInterner,
        literal_interner: &'d LiteralInterner,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        // 短路：URL 列表为空直接返回
        let urls = evidence.urls;
        if urls.is_empty() {
            return;
        }

        // 核心修复：获取引用而非移动所有权（避免 move 错误）
        let (literals_hit_ids, any_hit_ids, contains_hit_ids) = (
            &evidence.literals_hit_ids,
            &evidence.any_hit_ids,
            &evidence.contains_hit_ids,
        );

        // 遍历 URL 列表执行匹配
        for url in urls {
            for pattern in patterns {
                let matcher = pattern.exec.get_matcher();
                
                // 带作用域修剪的模式匹配（适配 ID 化参数）
                if pattern.matches_with_prune(
                    url,
                    //filtered_token_ids,
                    literals_hit_ids,
                    any_hit_ids,
                    contains_hit_ids,
                    //token_interner,
                    literal_interner,
                ) {
                    // 基于捕获组提取版本信息
                    let version = matcher
                        .captures(url)
                        .and_then(|cap| VersionExtractor::extract(&pattern.exec.version_template, &cap));
                    
                    // 更新检测结果（适配 matcher.describe 的 interner 参数）
                    handle_match_success(
                        Self::TYPE_NAME,
                        tech_name,
                        url,
                        url,
                        &version,
                        Some(pattern.exec.confidence),
                        &matcher.describe(literal_interner),
                        detected,
                    );
                    break; // 单 URL 匹配成功后终止规则遍历
                }
            }
        }
    }
}

impl UrlAnalyzer {
    /// 启动 URL 分析流程
    /// 
    /// # 参数
    /// - `runtime_lib`: 运行时规则库
    /// - `urls`: URL 列表（&[&str] 类型，零拷贝）
    /// - `detected`: 检测结果输出
    #[inline(always)]
    pub fn analyze(
        runtime_lib: &RuleLibraryRuntime,
        urls: &[&str],
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        let url_evidence = UrlEvidence::new(urls);
        <Self as Analyzer<[CompiledPattern], UrlEvidence>>::analyze(
            runtime_lib,
            &url_evidence,
            Scope::Url,
            detected,
        );
    }
}

/// URL 证据载体（Sized 类型，适配通用 Analyzer 骨架）
/// 
/// 封装 URL 列表及配套的 Token/hit 集合，满足 AnalyzerInput 接口约束
#[derive(Debug)]
pub struct UrlEvidence<'a> {
    /// URL 列表（切片引用，零拷贝）
    pub urls: &'a [&'a str],
    /// 空 TokenId 集合（兼容通用骨架）
    ///empty_token_ids: FxHashSet<TokenId>,
    /// LiteralId 命中集合（ID 化适配）
    literals_hit_ids: FxHashSet<LiteralId>,
    /// Any LiteralId 命中集合（ID 化适配）
    any_hit_ids: FxHashSet<LiteralId>,
    /// Contains LiteralId 命中集合（ID 化适配）
    contains_hit_ids: FxHashSet<LiteralId>,
    /// 空字符串集合（用于兼容 AnalyzerInput 接口的字符串方法）
    empty_str_set: FxHashSet<LiteralId>,
}

impl<'a> UrlEvidence<'a> {
    /// 快速构建 UrlEvidence 实例
    #[inline(always)]
    pub fn new(urls: &'a [&'a str]) -> Self {
        Self {
            urls,
            //empty_token_ids: FxHashSet::default(),
            literals_hit_ids: FxHashSet::default(),
            any_hit_ids: FxHashSet::default(),
            contains_hit_ids: FxHashSet::default(),
            empty_str_set: FxHashSet::default(), // 初始化空字符串集合
        }
    }
}

// 完整实现 AnalyzerInput 接口（4 个方法全部实现）
impl<'a> AnalyzerInput for UrlEvidence<'a> {
    // /// 返回空 TokenId 集合（URL 维度暂不提取 Token）
    // fn get_extracted_token_ids(&self) -> &FxHashSet<TokenId> {
    //     &self.empty_token_ids
    // }

    /// 返回空字符串集合（URL 维度暂不处理 Contains 字符串命中）
    fn get_contains_hit_ids(&self) -> &FxHashSet<LiteralId> {
        &self.empty_str_set
    }

    /// 返回空字符串集合（URL 维度暂不处理 Literals 字符串命中）
    fn get_literal_hit_ids(&self) -> &FxHashSet<LiteralId> {
        &self.empty_str_set
    }

    /// 返回空字符串集合（URL 维度暂不处理 Any 字符串命中）
    fn get_any_hit_ids(&self) -> &FxHashSet<LiteralId> {
        &self.empty_str_set
    }
}