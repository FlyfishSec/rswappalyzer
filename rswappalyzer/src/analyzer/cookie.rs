//! Cookie 分析器：基于 HTTP Cookie 信息匹配技术检测规则

use rswappalyzer_engine::{
    CompiledPattern, CompiledTechRule, RuleLibraryRuntime, Scope, compiled::{LiteralInterner}, input_evidence::header_evidence::HeaderEvidence
};
use rustc_hash::{FxHashMap};

use crate::{
    analyzer::{
        common::{handle_match_success},
        Analyzer,
    },
    VersionExtractor,
};

/// Cookie 维度分析器，实现通用 Analyzer 接口
/// 核心能力：基于标准化 Cookie 结构检测技术，支持存在性/正则匹配 + 版本提取
pub struct CookieAnalyzer;

impl Analyzer<FxHashMap<String, Vec<CompiledPattern>>, HeaderEvidence<'_>> for CookieAnalyzer {
    /// 分析器类型标识
    const TYPE_NAME: &'static str = "Cookie";

    /// 获取技术规则中的 Cookie 模式映射表
    fn get_patterns(tech: &CompiledTechRule) -> Option<&FxHashMap<String, Vec<CompiledPattern>>> {
        tech.cookie_patterns.as_ref()
    }

    /// Cookie 规则匹配核心逻辑
    /// 
    /// # 生命周期
    /// - `'d`: 绑定过滤后 Token 的引用生命周期
    /// 
    /// # 参数
    /// - `tech_name`: 待检测技术名称
    /// - `cookie_patterns`: Cookie 规则模式映射表（名称→模式列表）
    /// - `evidence`: Header 输入证据（包含标准化 Cookie 数据）
    /// - `filtered_tokens`: 作用域过滤后的 Token 集合（&String 类型）
    /// - `detected`: 检测结果（置信度, 版本）映射表
    fn match_logic<'d>(
        tech_name: &str,
        cookie_patterns: &FxHashMap<String, Vec<CompiledPattern>>,
        evidence: &HeaderEvidence<'_>,
        //filtered_token_ids: &FxHashSet<TokenId>,
        //token_interner: &'d TokenInterner,
        literal_interner: &'d LiteralInterner,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) {
        // 零拷贝转换为 &str 集合（和其他分析器保持一致）
        //let filtered_tokens_str = convert_string_ref_set_to_str_set(filtered_tokens);
        //let (literals_hit_lc_str, any_hit_lc_str, contains_hit_lc_str) = evidence.get_all_str_sets();
        let (literals_hit_ids, any_hit_ids, contains_hit_ids) = (
            &evidence.literals_hit_ids,
            &evidence.any_hit_ids,
            &evidence.contains_hit_ids,
        );

        // 构建 Cookie 名称 -> 取值列表的映射（零拷贝）
        let mut cookie_name_to_values: FxHashMap<&str, Vec<&str>> = FxHashMap::default();
        for cookie in evidence.cookies {
            cookie_name_to_values
                .entry(&cookie.name)
                .or_default()
                .push(&cookie.value);
        }

        // 遍历 Cookie 规则模式（按名称分组）
        for (rule_cookie_name, patterns) in cookie_patterns {
            // 跳过不存在的 Cookie
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
                        break;
                    }
                    // 分支2：正则/包含匹配（检查 Cookie 值并提取版本）
                    else if pattern.matches_with_prune(
                        cookie_val,
                //filtered_token_ids,
                &literals_hit_ids,
                &any_hit_ids,
                &contains_hit_ids,
                //token_interner,
                literal_interner,
                    ) {
                        confidence = Some(pattern.exec.confidence);
                        // 基于捕获组提取版本信息
                        version = matcher
                            .captures(cookie_val)
                            .and_then(|cap| VersionExtractor::extract(&pattern.exec.version_template, &cap));
                        break;
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
                    break; // 单取值匹配成功，终止遍历
                }
            }
        }
    }
}

impl CookieAnalyzer {
    /// 启动 Cookie 分析流程
    /// 
    /// # 参数
    /// - `runtime_lib`: 运行时规则库
    /// - `evidence`: Header 输入证据（包含 Cookie 数据）
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
            Scope::Cookie,
            detected,
        );
    }
}