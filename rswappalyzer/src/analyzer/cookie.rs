use rswappalyzer_engine::{
    header_evidence::HeaderEvidence, scope_pruner::PruneScope, CompiledPattern, CompiledTechRule,
    RuleLibraryRuntime,
};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::{
    analyzer::{common::handle_match_success, Analyzer},
    VersionExtractor,
};

/// Cookie 维度分析器（适配通用 Analyzer 骨架，基于 HeaderEvidence 载体）
/// 核心能力：基于标准化 Cookie 结构匹配技术规则（支持存在性/正则匹配 + 版本提取）
pub struct CookieAnalyzer;

/// 实现通用 Analyzer 骨架，绑定 HeaderEvidence 作为数据载体
impl Analyzer<FxHashMap<String, Vec<CompiledPattern>>, HeaderEvidence<'_>> for CookieAnalyzer {
    /// 分析器类型标识
    const TYPE_NAME: &'static str = "Cookie";

    /// 提取技术规则中的 Cookie 模式映射表
    /// 返回：Cookie 规则模式映射（Key: Cookie 名称，Value: 规则模式列表）
    fn get_patterns(tech: &CompiledTechRule) -> Option<&FxHashMap<String, Vec<CompiledPattern>>> {
        tech.cookie_patterns.as_ref()
    }

    /// Cookie 规则匹配核心逻辑（适配 StandardCookie 结构体）
    /// 参数：
    /// - tech_name: 技术名称
    /// - cookie_patterns: Cookie 规则模式映射表
    /// - evidence: HeaderEvidence 载体（包含标准化 Cookie 列表）
    /// - input_tokens: 预提取的 Token 集合（Header + Cookie 合并 Token）
    /// - detected: 检测结果存储容器
    fn match_logic(
        tech_name: &str,
        cookie_patterns: &FxHashMap<String, Vec<CompiledPattern>>,
        evidence: &HeaderEvidence,
        input_tokens: &FxHashSet<String>,
        literals_hit_lc: &FxHashSet<String>,
        any_hit_lc: &FxHashSet<String>,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        // 构建 Cookie 名称 -> 取值列表的映射（适配原有逻辑，兼容 StandardCookie）
        let mut cookie_name_to_values: FxHashMap<&str, Vec<&str>> = FxHashMap::default();
        for cookie in evidence.cookies {
            cookie_name_to_values
                .entry(&cookie.name)
                .or_default()
                .push(&cookie.value);
        }

        // 遍历 Cookie 规则模式（按 Cookie 名称分组）
        for (rule_cookie_name, patterns) in cookie_patterns {
            // 检查 Cookie 是否存在（基于标准化 Cookie 名称匹配）
            let Some(cookie_values) = cookie_name_to_values.get(rule_cookie_name.as_str()) else {
                continue;
            };

            // 遍历当前 Cookie 的所有取值
            for cookie_val in cookie_values {
                let mut confidence: Option<u8> = None;
                let mut version: Option<String> = None;

                // 遍历规则模式执行匹配
                for pattern in patterns {
                    let matcher = pattern.exec.get_matcher();

                    // 分支1：存在性匹配（仅检查 Cookie 存在）
                    if matcher.is_exists() {
                        confidence = Some(pattern.exec.confidence);
                        break; // 存在性匹配成功，终止规则遍历
                    }
                    // 分支2：正则/包含匹配（检查 Cookie 值并提取版本）
                    else if pattern.matches_with_prune(
                        cookie_val,
                        input_tokens,
                        &literals_hit_lc,
                        &any_hit_lc,
                    ) {
                        confidence = Some(pattern.exec.confidence);
                        // 版本提取（基于规则模板和捕获组）
                        version = matcher.captures(cookie_val).and_then(|cap| {
                            VersionExtractor::extract(&pattern.exec.version_template, &cap)
                        });
                        break; // 匹配成功，终止规则遍历
                    }
                }

                // 匹配成功：更新检测结果
                if confidence.is_some() {
                    handle_match_success(
                        Self::TYPE_NAME,
                        tech_name,
                        rule_cookie_name,
                        cookie_val,
                        &version,
                        confidence,
                        rule_cookie_name,
                        detected,
                    );
                    break; // 单 Cookie 取值匹配成功，终止取值遍历
                }
            }
        }
    }
}

impl CookieAnalyzer {
    /// Cookie 分析器入口方法（兼容原有调用逻辑，接收 HeaderEvidence）
    /// 参数：
    /// - runtime_lib: 运行时规则库
    /// - evidence: HeaderEvidence 载体（包含标准化 Cookie 数据）
    /// - detected: 检测结果输出容器
    #[inline(always)]
    pub fn analyze(
        runtime_lib: &RuleLibraryRuntime,
        evidence: &HeaderEvidence,
        literals_hit_lc: &FxHashSet<String>,
        any_hit_lc: &FxHashSet<String>,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        // 调用通用分析骨架（Cookie 维度剪枝）
        <Self as Analyzer<FxHashMap<String, Vec<CompiledPattern>>, HeaderEvidence<'_>>>::analyze(
            runtime_lib,
            evidence, // 传入 HeaderEvidence 载体
            PruneScope::Cookie,
            literals_hit_lc,
            any_hit_lc,
            detected,
        );
    }
}
