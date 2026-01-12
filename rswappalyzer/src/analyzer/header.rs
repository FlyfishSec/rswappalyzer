use rswappalyzer_engine::{
    header_evidence::HeaderEvidence, scope_pruner::PruneScope, CompiledPattern, CompiledTechRule,
    RuleLibraryRuntime,
};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::{
    analyzer::{common::handle_match_success, Analyzer},
    VersionExtractor,
};

/// HTTP Header 维度分析器（适配通用 Analyzer 骨架）
/// 核心能力：基于 HTTP 响应头匹配服务器/框架技术规则（支持存在性/正则匹配）
pub struct HeaderAnalyzer;

/// 实现通用 Analyzer 骨架，绑定 HeaderEvidence 作为数据载体
impl Analyzer<FxHashMap<String, Vec<CompiledPattern>>, HeaderEvidence<'_>> for HeaderAnalyzer {
    /// 分析器类型标识
    const TYPE_NAME: &'static str = "Header";

    /// 提取技术规则中的 Header 模式映射表
    /// 返回：Header 规则模式映射（Key: 响应头名称，Value: 规则模式列表）
    fn get_patterns(tech: &CompiledTechRule) -> Option<&FxHashMap<String, Vec<CompiledPattern>>> {
        tech.header_patterns.as_ref()
    }

    /// Header 规则匹配核心逻辑
    /// 支持两种匹配模式：
    /// 1. 存在性匹配：仅检查响应头是否存在
    /// 2. 正则/包含匹配：检查头内容并提取版本
    /// 参数：
    /// - tech_name: 技术名称
    /// - header_patterns: Header 规则模式映射表
    /// - evidence: Header 证据载体（包含响应头/Token 等数据）
    /// - input_tokens: 预提取的 Token 集合（引用传递，零拷贝）
    /// - detected: 检测结果存储容器
    fn match_logic(
        tech_name: &str,
        header_patterns: &FxHashMap<String, Vec<CompiledPattern>>,
        evidence: &HeaderEvidence,
        input_tokens: &FxHashSet<String>,
        literals_hit_lc: &FxHashSet<String>,
        any_hit_lc: &FxHashSet<String>,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        // 从证据载体提取 Header 映射表
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
                //if matcher.describe().contains("microsoft-") {println!("{:?}",literals_hit_lc);}
                // 分支1：存在性匹配（仅检查 Header 是否存在）
                if matcher.is_exists() {
                    if header_val.is_some() {
                        matched = true;
                        matched_rule = matcher.describe();
                        confidence = Some(pattern.exec.confidence);
                    }
                }
                // 分支2：正则/包含匹配（检查 Header 内容并提取版本）
                else if let Some(val) = header_val {
                    if pattern.matches_with_prune(val, input_tokens, literals_hit_lc, any_hit_lc) {
                        matched = true;
                        matched_rule = matcher.describe();
                        confidence = Some(pattern.exec.confidence);
                        // 版本提取（基于规则模板和捕获组）
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
    /// Header 分析器入口方法
    /// 参数：
    /// - runtime_lib: 运行时规则库
    /// - evidence: Header 证据载体（包含响应头/Token 等数据）
    /// - detected: 检测结果输出容器
    #[inline(always)]
    pub fn analyze(
        runtime_lib: &RuleLibraryRuntime,
        evidence: &HeaderEvidence,
        literals_hit_lc: &FxHashSet<String>,
        any_hit_lc: &FxHashSet<String>,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        // 调用通用分析骨架（Header 维度剪枝）
        <Self as Analyzer<FxHashMap<String, Vec<CompiledPattern>>, HeaderEvidence<'_>>>::analyze(
            runtime_lib,
            evidence,
            PruneScope::Header,
            literals_hit_lc,
            any_hit_lc,
            detected,
        );
    }
}
