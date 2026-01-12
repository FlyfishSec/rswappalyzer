use rswappalyzer_engine::{
    scope_pruner::PruneScope, CompiledPattern, CompiledTechRule, RuleLibraryRuntime,
};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::{
    analyzer::{common::handle_match_success, Analyzer},
    VersionExtractor,
};

/// URL 维度分析器（适配通用 Analyzer 骨架，基于 UrlEvidence 载体）
pub struct UrlAnalyzer;

// 绑定 UrlEvidence（Sized 类型，彻底解决 DST 约束问题）
impl<'a> Analyzer<[CompiledPattern], UrlEvidence<'a>> for UrlAnalyzer {
    /// 分析器类型标识
    const TYPE_NAME: &'static str = "URL";

    /// 提取技术规则中的 URL 模式集合
    fn get_patterns(tech: &CompiledTechRule) -> Option<&[CompiledPattern]> {
        tech.url_patterns.as_deref()
    }

    /// URL 规则匹配核心逻辑
    fn match_logic(
        tech_name: &str,
        patterns: &[CompiledPattern],
        evidence: &UrlEvidence,
        input_tokens: &FxHashSet<String>,
        literals_hit_lc: &FxHashSet<String>,
        any_hit_lc: &FxHashSet<String>,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        // 从 UrlEvidence 提取 URL 列表（零拷贝）
        let urls = evidence.urls;

        // 遍历 URL 列表执行匹配（原有逻辑完全保留）
        for url in urls {
            for pattern in patterns {
                let matcher = pattern.exec.get_matcher();
                // 类型完全匹配，无编译错误
                if pattern.matches_with_prune(url, input_tokens, literals_hit_lc, any_hit_lc) {
                    // 版本提取（基于规则模板和捕获组）
                    let version = matcher.captures(url).and_then(|cap| {
                        VersionExtractor::extract(&pattern.exec.version_template, &cap)
                    });
                    // 匹配成功处理
                    handle_match_success(
                        Self::TYPE_NAME,
                        tech_name,
                        url,
                        url,
                        &version,
                        Some(pattern.exec.confidence),
                        &matcher.describe(),
                        detected,
                    );
                    break; // 单 URL 匹配成功后终止规则遍历
                }
            }
        }
    }
}

impl UrlAnalyzer {
    /// URL 分析器入口方法（兼容原有 &[&str] 调用参数）
    #[inline(always)]
    pub fn analyze(
        runtime_lib: &RuleLibraryRuntime,
        urls: &[&str],
        literals_hit_lc: &FxHashSet<String>,
        any_hit_lc: &FxHashSet<String>,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        // 快速构建 UrlEvidence（无性能损耗）
        let url_evidence = UrlEvidence::new(urls);

        // 调用通用分析骨架（Sized 类型，无编译错误）
        <Self as Analyzer<[CompiledPattern], UrlEvidence>>::analyze(
            runtime_lib,
            &url_evidence, // 传入 UrlEvidence 引用（Sized）
            PruneScope::Url,
            literals_hit_lc,
            any_hit_lc,
            detected,
        );
    }
}

/// URL 证据载体（Sized 类型，适配通用 Analyzer 骨架）
#[derive(Debug)]
pub struct UrlEvidence<'a> {
    /// URL 列表（切片引用，零拷贝）
    pub urls: &'a [&'a str],
    /// 空 Token 集合（兼容通用骨架，无实际数据）
    empty_tokens: FxHashSet<String>,
    #[allow(dead_code)]
    literals_hit: FxHashSet<&'a str>,
    #[allow(dead_code)]
    any_hit: FxHashSet<&'a str>,
}

impl<'a> UrlEvidence<'a> {
    /// 快速构建 UrlEvidence
    #[inline(always)]
    pub fn new(urls: &'a [&'a str]) -> Self {
        Self {
            urls,
            empty_tokens: FxHashSet::default(),
            literals_hit: FxHashSet::default(),
            any_hit: FxHashSet::default(),
        }
    }
}

// 为 UrlEvidence 实现 AnalyzerInput
impl<'a> crate::analyzer::AnalyzerInput for UrlEvidence<'a> {
    /// 返回空 Token 集合
    fn get_extracted_tokens(&self) -> &FxHashSet<String> {
        &self.empty_tokens
    }
}
