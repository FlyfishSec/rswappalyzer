//! Tech detector core module
//! 技术检测器核心
//! 核心职责：
//! 1. 规则库加载与编译（内置/本地/远程规则）
//! 2. 多维度技术检测（URL/Header/Cookie/HTML/Script/Meta）
//! 3. 检测结果聚合与关联推导
//! 4. 提供基础检测/带耗时统计/HashMap输入等多版本接口

use crate::analyzer::{
    cookie::CookieAnalyzer, header::HeaderAnalyzer, html::HtmlAnalyzer, meta::MetaAnalyzer,
    script::ScriptAnalyzer, url::UrlAnalyzer,
};
use crate::error::{RswResult, RswappalyzerError};
use crate::result::detect_result::Technology;
use crate::utils::extractor::html_input_guard::HtmlInputGuard;
use crate::utils::{build_lower_hit_index, DetectionUpdater, HeaderConverter};
use crate::{DetectResult, HtmlExtractor, RuleConfig, RuleOrigin};
// 仅在embedded-rules开启时导入rswappalyzer_rules
#[cfg(feature = "embedded-rules")]
use crate::rswappalyzer_rules;
use crate::RuleLoader;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use rswappalyzer_engine::ac_manager::AcAutomatonCache;
use rswappalyzer_engine::header_evidence::HeaderEvidence;
use rswappalyzer_engine::html_evidence::HtmlEvidence;
use rswappalyzer_engine::{
    CompiledRuleLibrary, CoreError, RuleIndexer, RuleLibrary, RuleLibraryIndex, RuleLibraryRuntime,
};
use rustc_hash::{FxHashMap, FxHashSet};
use std::borrow::Cow;
use std::sync::Arc;
use std::time::Instant;

/// 技术检测器核心结构体
/// 设计说明：
/// - compiled_lib: 编译后的规则库（Arc共享，避免重复编译）
/// - config: 规则配置（保留配置上下文）
/// - rule_index: 规则库索引（可选，用于调试和扩展）
#[derive(Debug, Clone)]
pub struct TechDetector {
    /// 运行时规则库
    runtime_lib: Arc<RuleLibraryRuntime>,
    /// 规则配置（保留配置上下文）
    #[allow(dead_code)]
    config: RuleConfig,
    /// 规则库索引（可选，用于调试和扩展）
    pub rule_index: Option<Arc<RuleLibraryIndex>>,
}

impl TechDetector {
    /// 使用内存中的RuleLibrary创建检测器
    /// 适用场景：预加载规则库后手动创建检测器
    /// 参数：
    /// - rule_lib: 内存中的规则库实例
    /// - config: 规则配置
    /// 返回：检测器实例 | 错误
    pub fn with_rules(rule_lib: RuleLibrary, config: RuleConfig) -> RswResult<Self> {
        // 构建规则库索引
        let rule_index = RuleLibraryIndex::from_rule_library(&rule_lib)?;
        // 编译规则库
        let compiled_lib = RuleIndexer::build_compiled_library(&rule_index, None)?;

        // 初始化AC自动机缓存
        let ac_cache = AcAutomatonCache::new(&compiled_lib).map_err(CoreError::from)?;

        // 构建运行时规则库
        let runtime_lib = RuleLibraryRuntime {
            compiled_lib: Arc::new(compiled_lib),
            ac_cache: Arc::new(ac_cache),
        };

        Ok(Self {
            runtime_lib: Arc::new(runtime_lib),
            config,
            rule_index: Some(Arc::new(rule_index)),
        })
    }

    /// 使用内置规则创建检测器（仅embedded-rules特性开启时可用）
    /// 特性：
    /// 1. 零耗时：使用预编译的内置规则库
    /// 2. 特性守卫：未开启特性时编译报错
    /// 参数：config - 规则配置
    /// 返回：检测器实例 | 错误
    #[cfg(feature = "embedded-rules")]
    pub fn with_embedded_rules(config: RuleConfig) -> RswResult<Self> {
        // 直接获取内嵌规则库的 Arc 引用（仅克隆指针，零成本）
        let compiled_lib = rswappalyzer_rules::EMBEDDED_COMPILED_LIB.clone();

        // 借用 Arc 指向的 CompiledRuleLibrary 创建 ac_cache（无移动/克隆成本）
        let ac_cache = AcAutomatonCache::new(&compiled_lib).map_err(CoreError::from)?;

        // 构建运行时规则库（仅移动 Arc 指针，无数据拷贝）
        let runtime_lib = RuleLibraryRuntime {
            compiled_lib, // Arc 克隆后移动，零成本
            ac_cache: Arc::new(ac_cache),
        };

        Ok(Self {
            runtime_lib: Arc::new(runtime_lib),
            config,
            rule_index: None,
        })
    }

    /// 使用已编译的规则库创建检测器
    /// 适用场景：自定义编译规则库后直接使用
    /// 参数：
    /// - compiled_lib: 已编译的规则库
    /// - rule_index: 规则库索引
    /// - config: 规则配置
    /// 返回：检测器实例
    pub fn with_compiled_lib(
        compiled_lib: CompiledRuleLibrary,
        rule_index: RuleLibraryIndex,
        config: RuleConfig,
    ) -> RswResult<Self> {
        // 借用 Arc 指向的 CompiledRuleLibrary 创建 ac_cache（无移动/克隆成本）
        let ac_cache = AcAutomatonCache::new(&compiled_lib).map_err(CoreError::from)?;

        // 构建运行时规则库（仅移动 Arc 指针，无数据拷贝）
        let runtime_lib = RuleLibraryRuntime {
            compiled_lib: Arc::new(compiled_lib),
            ac_cache: Arc::new(ac_cache),
        };

        Ok(Self {
            runtime_lib: Arc::new(runtime_lib),
            config,
            rule_index: Some(Arc::new(rule_index)),
        })
    }

    /// 创建技术检测器（基础版，无耗时日志）
    /// 支持规则来源：
    /// 1. Embedded：内置规则（需开启embedded-rules特性）
    /// 2. LocalFile/RemoteOfficial/RemoteCustom：运行时加载
    /// 参数：config - 规则配置
    /// 返回：检测器实例 | 错误
    pub async fn new(config: RuleConfig) -> RswResult<Self> {
        match &config.origin {
            // Embedded模式 - 特性守卫 + 降级处理
            RuleOrigin::Embedded => {
                #[cfg(feature = "embedded-rules")]
                {
                    Self::with_embedded_rules(config)
                }
                // 关闭特性时，返回明确的错误
                #[cfg(not(feature = "embedded-rules"))]
                {
                    return Err(RswappalyzerError::FeatureDisabled(
                        "embedded-rules feature is disabled, cannot use embedded rule library. Please enable this feature or use local/remote rules.".to_string()
                    ));
                }
            }

            // 运行时加载模式（本地/远程规则）
            RuleOrigin::LocalFile(_) | RuleOrigin::RemoteOfficial | RuleOrigin::RemoteCustom(_) => {
                // 1. 加载规则库（优先从缓存加载）
                let rule_loader = RuleLoader::new();
                let rule_lib = rule_loader.load(&config).await?;

                // 2. 构建规则库索引
                let rule_index = RuleLibraryIndex::from_rule_library(&rule_lib)?;

                // 3. 编译规则库
                let compiled_lib = RuleIndexer::build_compiled_library(
                    &rule_index,
                    Some("data/categories_data.json"),
                )?;

                let ac_cache = AcAutomatonCache::new(&compiled_lib).map_err(CoreError::from)?;

                // 构建运行时规则库
                let runtime_lib = RuleLibraryRuntime {
                    compiled_lib: Arc::new(compiled_lib),
                    ac_cache: Arc::new(ac_cache),
                };

                Ok(Self {
                    runtime_lib: Arc::new(runtime_lib),
                    config,
                    rule_index: Some(Arc::new(rule_index)),
                })
            }
        }
    }

    /// 核心检测方法（高性能版，无耗时统计）
    /// 检测维度：URL/Header/Cookie/HTML/Script/Meta
    /// 参数：
    /// - headers: HTTP头信息（HeaderMap）
    /// - urls: 检测的URL列表
    /// - body: HTTP响应体（字节数组）
    /// 返回：检测结果 | 错误
    #[inline(always)]
    pub fn detect(
        &self,
        headers: &HeaderMap,
        urls: &[&str],
        body: &[u8],
    ) -> RswResult<DetectResult> {
        // 1. Header转换（拆分单值Header和Cookie Header）
        let (single_header_map, cookie_header_map) = HeaderConverter::convert_all(&headers);
        let standard_cookies = HeaderConverter::parse_to_standard_cookie(&cookie_header_map);

        // 提取Header/Cookie Token
        let mut header_tokens = FxHashSet::default();
        // Header key+value Token提取
        for (k, v) in &single_header_map {
            header_tokens
                .extend(crate::utils::extractor::token_extract_zh::extract_input_tokens(k));
            header_tokens
                .extend(crate::utils::extractor::token_extract_zh::extract_input_tokens(v));
        }
        // Cookie name+value Token提取
        for c in &standard_cookies {
            header_tokens
                .extend(crate::utils::extractor::token_extract_zh::extract_input_tokens(&c.name));
            header_tokens
                .extend(crate::utils::extractor::token_extract_zh::extract_input_tokens(&c.value));
        }

        // 构建HeaderEvidence
        let header_evidence = HeaderEvidence::build(
            &single_header_map,
            &standard_cookies,
            &self.runtime_lib.ac_cache.header_literal_ac,
            &self.runtime_lib.ac_cache.header_any_ac,
            header_tokens,
        );

        // 构建Header小写命中索引（一次性）
        let header_literals_hit_lc = build_lower_hit_index(&header_evidence.literals_hit);
        let header_any_hit_lc = build_lower_hit_index(&header_evidence.any_hit);

        // 2. HTML处理（输入守卫 + 内容提取，零拷贝优化）
        let html_str = String::from_utf8_lossy(body);
        let (html_safe_str, script_src_combined, meta_tags) = match HtmlInputGuard::guard(html_str)
        {
            Some(valid_html) => {
                let html_result = HtmlExtractor::extract(&valid_html);
                (
                    valid_html,
                    html_result.script_src_combined,
                    html_result.meta_tags,
                )
            }
            None => (Cow::Borrowed(""), String::new(), Vec::with_capacity(0)),
        };

        // 初始化HTML相关变量（修复作用域问题）
        let (html_evidence, html_literals_hit_lc, html_any_hit_lc) = if !html_safe_str.is_empty() {
            let html_tokens =
                crate::utils::extractor::token_extract_zh::extract_input_tokens(&html_safe_str);

            let evidence = HtmlEvidence::build(
                &html_safe_str,
                &script_src_combined,
                &meta_tags,
                &self.runtime_lib.ac_cache.html_literal_ac,
                &self.runtime_lib.ac_cache.html_any_ac,
                html_tokens,
            );

            // 构建HTML小写命中索引（一次性）
            let literals_hit_lc = build_lower_hit_index(&evidence.literals_hit);
            let any_hit_lc = build_lower_hit_index(&evidence.any_hit);

            (Some(evidence), literals_hit_lc, any_hit_lc)
        } else {
            // 无HTML内容时初始化空值
            (None, FxHashSet::default(), FxHashSet::default())
        };

        // 3. 初始化检测结果
        let mut detected = FxHashMap::default();

        // 4. 多维度分析
        UrlAnalyzer::analyze(
            &self.runtime_lib,
            urls,
            &FxHashSet::default(),
            &FxHashSet::default(),
            &mut detected,
        );
        // Header分析：传入HeaderEvidence
        HeaderAnalyzer::analyze(
            &self.runtime_lib,
            &header_evidence,
            &header_literals_hit_lc,
            &header_any_hit_lc,
            &mut detected,
        );

        // Cookie分析：复用HeaderEvidence（已包含Cookie数据）
        CookieAnalyzer::analyze(
            &self.runtime_lib,
            &header_evidence,
            &header_literals_hit_lc,
            &header_any_hit_lc,
            &mut detected,
        );

        // 有有效HTML内容时才执行HTML相关分析
        if let Some(ref evidence) = html_evidence {
            HtmlAnalyzer::analyze(
                &self.runtime_lib,
                evidence,
                &html_literals_hit_lc,
                &html_any_hit_lc,
                &mut detected,
            );
            ScriptAnalyzer::analyze(
                &self.runtime_lib,
                evidence,
                &html_literals_hit_lc,
                &html_any_hit_lc,
                &mut detected,
            );
            MetaAnalyzer::analyze(
                &self.runtime_lib,
                evidence,
                &html_literals_hit_lc,
                &html_any_hit_lc,
                &mut detected,
            );
        }

        // 5. 应用关联推导规则
        let imply_map =
            DetectionUpdater::apply_implies(&self.runtime_lib.compiled_lib, &mut detected);

        // 6. 聚合最终结果
        let mut technologies = Vec::with_capacity(detected.len());
        for (rule_id, (confidence, version)) in detected {
            if let Some(compiled_tech) = self.runtime_lib.compiled_lib.tech_patterns.get(&rule_id) {
                // 构建技术分类列表
                let categories = compiled_tech
                    .category_ids
                    .iter()
                    .filter_map(|id| self.runtime_lib.compiled_lib.category_map.get(id).cloned())
                    .collect();

                // 获取推导来源
                let implied_by = imply_map.get(&compiled_tech.name).cloned();

                // 构建Technology对象
                let tech = Technology {
                    name: compiled_tech.name.clone(),
                    version,
                    categories,
                    confidence,
                    implied_by,
                    // 仅在full-meta特性开启时初始化这些字段
                    #[cfg(feature = "full-meta")]
                    website: {
                        let default_meta = TechBasicInfo::default();
                        let tech_meta = self
                            .runtime_lib
                            .compiled_lib
                            .tech_meta
                            .get(&rule_id)
                            .unwrap_or(&default_meta);
                        tech_meta.website.clone()
                    },
                    #[cfg(feature = "full-meta")]
                    description: {
                        let default_meta = TechBasicInfo::default();
                        let tech_meta = self
                            .runtime_lib
                            .compiled_lib
                            .tech_meta
                            .get(&rule_id)
                            .unwrap_or(&default_meta);
                        tech_meta.description.clone()
                    },
                    #[cfg(feature = "full-meta")]
                    icon: {
                        let default_meta = TechBasicInfo::default();
                        let tech_meta = self
                            .runtime_lib
                            .compiled_lib
                            .tech_meta
                            .get(&rule_id)
                            .unwrap_or(&default_meta);
                        tech_meta.icon.clone()
                    },
                    #[cfg(feature = "full-meta")]
                    cpe: {
                        let default_meta = TechBasicInfo::default();
                        let tech_meta = self
                            .runtime_lib
                            .compiled_lib
                            .tech_meta
                            .get(&rule_id)
                            .unwrap_or(&default_meta);
                        tech_meta.cpe.clone()
                    },
                    #[cfg(feature = "full-meta")]
                    saas: {
                        let default_meta = TechBasicInfo::default();
                        let tech_meta = self
                            .runtime_lib
                            .compiled_lib
                            .tech_meta
                            .get(&rule_id)
                            .unwrap_or(&default_meta);
                        Some(tech_meta.saas)
                    },
                    #[cfg(feature = "full-meta")]
                    pricing: {
                        let default_meta = TechBasicInfo::default();
                        let tech_meta = self
                            .runtime_lib
                            .compiled_lib
                            .tech_meta
                            .get(&rule_id)
                            .unwrap_or(&default_meta);
                        tech_meta.pricing.clone()
                    },
                };

                technologies.push(tech);
            }
        }

        Ok(DetectResult { technologies })
    }

    /// 核心检测方法（带全阶段耗时统计+详细日志）
    /// 特性：
    /// 1. 分阶段计时：Header转换/HTML解析/各维度分析/结果聚合
    /// 2. 详细日志：每个阶段的耗时、数据量、检测进度
    /// 3. 兼容基础版检测逻辑，仅增加统计和日志
    /// 参数：
    /// - headers: HTTP头信息（HeaderMap）
    /// - urls: 检测的URL列表
    /// - body: HTTP响应体（字节数组）
    /// 返回：检测结果 | 错误
    #[inline(always)]
    pub fn detect_log(
        &self,
        headers: &HeaderMap,
        urls: &[&str],
        body: &[u8],
    ) -> RswResult<DetectResult> {
        let total_start = Instant::now();

        // 1. Header转换 + 耗时统计
        let header_conv_start = Instant::now();
        let (single_header_map, cookie_header_map) = HeaderConverter::convert_all(&headers);
        let header_conv_cost = header_conv_start.elapsed();
        println!(
            "[Performance] Header conversion completed | Time: {}ms ({:?}) | Single-value header count: {} | Cookie header count: {}",
            header_conv_cost.as_millis(),
            header_conv_cost,
            single_header_map.len(),
            cookie_header_map.len()
        );
        let standard_cookies = HeaderConverter::parse_to_standard_cookie(&cookie_header_map);

        // 提取Header/Cookie Token
        let mut header_tokens = FxHashSet::default();
        // Header key+value Token提取
        for (k, v) in &single_header_map {
            header_tokens
                .extend(crate::utils::extractor::token_extract_zh::extract_input_tokens(k));
            header_tokens
                .extend(crate::utils::extractor::token_extract_zh::extract_input_tokens(v));
        }
        // Cookie name+value Token提取
        for c in &standard_cookies {
            header_tokens
                .extend(crate::utils::extractor::token_extract_zh::extract_input_tokens(&c.name));
            header_tokens
                .extend(crate::utils::extractor::token_extract_zh::extract_input_tokens(&c.value));
        }

        // 构建HeaderEvidence
        let header_evidence = HeaderEvidence::build(
            &single_header_map,
            &standard_cookies,
            &self.runtime_lib.ac_cache.header_literal_ac,
            &self.runtime_lib.ac_cache.header_any_ac,
            header_tokens,
        );

        // 构建Header小写命中索引（一次性）
        let header_literals_hit_lc = build_lower_hit_index(&header_evidence.literals_hit);
        let header_any_hit_lc = build_lower_hit_index(&header_evidence.any_hit);

        //if header_literals_hit_lc.contains("iis") {log::error!{"{:?}",header_any_hit_lc};}
        // 调试打印：检查server头是否被扫描，以及literals_hit是否有iis
        // if let Some(server_val) = single_header_map.get("server") {
        //     println!("[DEBUG] Server头值: {}", server_val);
        //     println!(
        //         "[DEBUG] Header literals_hit_lc: {:?}",
        //         header_literals_hit_lc
        //     );
        //     println!(
        //         "[DEBUG] 是否包含iis: {}",
        //         header_literals_hit_lc.contains("iis")
        //     );
        // }

        // 2. HTML解析与提取 + 耗时统计
        let html_parse_start = Instant::now();
        let html_str = String::from_utf8_lossy(body);
        let (html_safe_str, script_src_combined, meta_tags) = match HtmlInputGuard::guard(html_str)
        {
            Some(valid_html) => {
                let html_result = HtmlExtractor::extract(&valid_html);
                (
                    valid_html,
                    html_result.script_src_combined,
                    html_result.meta_tags,
                )
            }
            None => (Cow::Borrowed(""), String::new(), Vec::with_capacity(0)),
        };
        let html_parse_cost = html_parse_start.elapsed();
        println!(
            "[Performance] HTML parsing & extraction completed | Time: {}ms ({:?}) | Valid HTML: {} | Script src length: {} | Meta tag count: {}",
            html_parse_cost.as_millis(),
            html_parse_cost,
            !html_safe_str.is_empty(),
            script_src_combined.len(),
            meta_tags.len()
        );

        // 构建HtmlEvidence
        let mut html_evidence = None;
        let mut html_literals_hit_lc = FxHashSet::default();
        let mut html_any_hit_lc = FxHashSet::default();
        if !html_safe_str.is_empty() {
            let html_tokens =
                crate::utils::extractor::token_extract_zh::extract_input_tokens(&html_safe_str);

            html_evidence = Some(HtmlEvidence::build(
                &html_safe_str,
                &script_src_combined,
                &meta_tags,
                &self.runtime_lib.ac_cache.html_literal_ac,
                &self.runtime_lib.ac_cache.html_any_ac,
                html_tokens,
            ));

            // 构建HTML小写命中索引（一次性）
            if let Some(ref evidence) = html_evidence {
                html_literals_hit_lc = build_lower_hit_index(&evidence.literals_hit);
                html_any_hit_lc = build_lower_hit_index(&evidence.any_hit);
            }
        }

        // 3. 初始化检测结果
        let mut detected = FxHashMap::default();

        // 4.1 URL维度分析 + 耗时统计
        let url_analyze_start = Instant::now();
        UrlAnalyzer::analyze(
            &self.runtime_lib,
            urls,
            &FxHashSet::default(),
            &FxHashSet::default(),
            &mut detected,
        );
        let url_analyze_cost = url_analyze_start.elapsed();
        println!(
            "[Performance] URL fingerprint analysis completed | Time: {}ms ({:?}) | Detected tech count: {}",
            url_analyze_cost.as_millis(),
            url_analyze_cost,
            detected.len()
        );

        // 4.2 Header维度分析 + 耗时统计
        let header_analyze_start = Instant::now();
        HeaderAnalyzer::analyze(
            &self.runtime_lib,
            &header_evidence,
            &header_literals_hit_lc,
            &header_any_hit_lc,
            &mut detected,
        );
        let header_analyze_cost = header_analyze_start.elapsed();
        println!(
            "[Performance] Header fingerprint analysis completed | Time: {}ms ({:?}) | Detected tech count: {}",
            header_analyze_cost.as_millis(),
            header_analyze_cost,
            detected.len()
        );

        // 4.3 Cookie维度分析 + 耗时统计
        let cookie_analyze_start = Instant::now();
        CookieAnalyzer::analyze(
            &self.runtime_lib,
            &header_evidence,
            &header_literals_hit_lc,
            &header_any_hit_lc,
            &mut detected,
        );
        let cookie_analyze_cost = cookie_analyze_start.elapsed();
        println!(
            "[Performance] Cookie fingerprint analysis completed | Time: {}ms ({:?}) | Detected tech count: {}",
            cookie_analyze_cost.as_millis(),
            cookie_analyze_cost,
            detected.len()
        );

        // 4.4 HTML相关维度分析（有有效HTML时执行）
        if !html_safe_str.is_empty() {
            // 4.4.1 HTML文本分析
            let html_analyze_start = Instant::now();
            if let Some(evidence) = &html_evidence {
                HtmlAnalyzer::analyze(
                    &self.runtime_lib,
                    evidence,
                    &html_literals_hit_lc,
                    &html_any_hit_lc,
                    &mut detected,
                );
            }
            let html_analyze_cost = html_analyze_start.elapsed();
            println!(
                "[Performance] HTML fingerprint analysis completed | Time: {}ms ({:?}) | Detected tech count: {}",
                html_analyze_cost.as_millis(),
                html_analyze_cost,
                detected.len()
            );

            // 4.4.2 Script脚本分析
            let script_analyze_start = Instant::now();
            if let Some(evidence) = &html_evidence {
                ScriptAnalyzer::analyze(
                    &self.runtime_lib,
                    evidence,
                    &html_literals_hit_lc,
                    &html_any_hit_lc,
                    &mut detected,
                );
            }
            let script_analyze_cost = script_analyze_start.elapsed();
            println!(
                "[Performance] Script fingerprint analysis completed | Time: {}ms ({:?}) | Detected tech count: {}",
                script_analyze_cost.as_millis(),
                script_analyze_cost,
                detected.len()
            );

            // 4.4.3 Meta标签分析
            let meta_analyze_start = Instant::now();
            if let Some(evidence) = &html_evidence {
                MetaAnalyzer::analyze(
                    &self.runtime_lib,
                    evidence,
                    &html_literals_hit_lc,
                    &html_any_hit_lc,
                    &mut detected,
                );
            }
            let meta_analyze_cost = meta_analyze_start.elapsed();
            println!(
                "[Performance] Meta fingerprint analysis completed | Time: {}ms ({:?}) | Detected tech count: {}",
                meta_analyze_cost.as_millis(),
                meta_analyze_cost,
                detected.len()
            );
        } else {
            println!("[Performance] No valid HTML content, skip HTML/Script/Meta analysis");
        }

        // 5. 关联规则推导 + 耗时统计
        let imply_start = Instant::now();
        let imply_map =
            DetectionUpdater::apply_implies(&self.runtime_lib.compiled_lib, &mut detected);
        let imply_cost = imply_start.elapsed();
        println!(
            "[Performance] Implication rule application completed | Time: {}ms ({:?}) | Implied tech count: {} | Total detected tech count: {}",
            imply_cost.as_millis(),
            imply_cost,
            imply_map.len(),
            detected.len()
        );

        // 6. 结果聚合 + 耗时统计
        let aggregate_start = Instant::now();
        let mut technologies = Vec::with_capacity(detected.len());
        for (rule_id, (confidence, version)) in detected {
            if let Some(compiled_tech) = self.runtime_lib.compiled_lib.tech_patterns.get(&rule_id) {
                let categories = compiled_tech
                    .category_ids
                    .iter()
                    .filter_map(|id| self.runtime_lib.compiled_lib.category_map.get(id).cloned())
                    .collect();
                let implied_by = imply_map.get(&compiled_tech.name).cloned();

                let tech = Technology {
                    name: compiled_tech.name.clone(),
                    version,
                    categories,
                    confidence,
                    implied_by,
                    #[cfg(feature = "full-meta")]
                    website: String::new(),
                    #[cfg(feature = "full-meta")]
                    description: String::new(),
                    #[cfg(feature = "full-meta")]
                    icon: String::new(),
                    #[cfg(feature = "full-meta")]
                    cpe: None,
                    #[cfg(feature = "full-meta")]
                    saas: false,
                    #[cfg(feature = "full-meta")]
                    pricing: None,
                };

                #[cfg(feature = "full-meta")]
                {
                    let default_meta = TechBasicInfo::default();
                    let tech_meta = self
                        .compiled_lib
                        .tech_meta
                        .get(&rule_id)
                        .unwrap_or(&default_meta);

                    tech.website = tech_meta.website.clone();
                    tech.description = tech_meta.description.clone();
                    tech.icon = tech_meta.icon.clone();
                    tech.cpe = tech_meta.cpe.clone();
                    tech.saas = tech_meta.saas;
                    tech.pricing = tech_meta.pricing.clone();
                }

                technologies.push(tech);
            }
        }

        let aggregate_cost = aggregate_start.elapsed();
        println!(
            "[Performance] Result aggregation completed | Time: {}ms ({:?}) | Final detected tech count: {}",
            aggregate_cost.as_millis(),
            aggregate_cost,
            technologies.len()
        );

        // 总耗时统计
        let total_cost = total_start.elapsed();
        println!("======================================================================");
        println!(
            "[Detection Complete] Full process finished | Total time: {}ms ({:?}) | Final tech count: {} | Implied tech count: {}",
            total_cost.as_millis(),
            total_cost,
            technologies.len(),
            imply_map.len()
        );
        println!("======================================================================");

        Ok(DetectResult { technologies })
    }

    /// 核心检测方法（HashMap输入版）
    /// 适用场景：Header以HashMap形式传入（非标准HeaderMap）
    /// 参数：
    /// - headers: Header哈希映射（String -> Vec<String>）
    /// - urls: 检测的URL列表
    /// - body: HTTP响应体（字节数组）
    /// 返回：检测结果 | 错误
    #[inline(always)]
    pub fn detect_with_hashmap(
        &self,
        headers: &FxHashMap<String, Vec<String>>,
        urls: &[&str],
        body: &[u8],
    ) -> RswResult<DetectResult> {
        // 转换为单值Header映射
        let single_header_map = HeaderConverter::to_single_value(headers);
        let mut header_map = HeaderMap::new();

        // 转换为标准HeaderMap
        for (key, value) in single_header_map {
            let header_name = HeaderName::from_bytes(key.as_bytes()).map_err(|e| {
                RswappalyzerError::InvalidInput(format!(
                    "Invalid header name: {}, error: {}",
                    key, e
                ))
            })?;
            let header_value = HeaderValue::from_str(&value).map_err(|e| {
                RswappalyzerError::InvalidInput(format!(
                    "Invalid header value: {}, error: {}",
                    value, e
                ))
            })?;
            header_map.append(header_name, header_value);
        }

        // 调用基础检测方法
        self.detect(&header_map, urls, body)
    }
}

/// 异步全局单例检测接口（基础版）
/// 特性：自动获取全局检测器实例，执行基础检测
/// 参数：
/// - headers: HTTP头信息（HeaderMap）
/// - urls: 检测的URL列表
/// - body: HTTP响应体（字节数组）
/// 返回：检测结果 | 错误
#[inline(always)]
pub async fn detect(headers: &HeaderMap, urls: &[&str], body: &[u8]) -> RswResult<DetectResult> {
    let detector = super::global::get_global_detector().await?;
    detector.detect(headers, urls, body)
}

/// 异步全局单例检测接口（带耗时统计版）
/// 特性：自动获取全局检测器实例，执行带耗时统计的检测
/// 参数：
/// - headers: HTTP头信息（HeaderMap）
/// - urls: 检测的URL列表
/// - body: HTTP响应体（字节数组）
/// 返回：检测结果 | 错误
#[inline(always)]
pub async fn detect_log(
    headers: &HeaderMap,
    urls: &[&str],
    body: &[u8],
) -> RswResult<DetectResult> {
    let detector = super::global::get_global_detector().await?;
    detector.detect_log(headers, urls, body)
}
