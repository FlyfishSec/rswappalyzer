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
use crate::utils::{DetectionUpdater, HeaderConverter};
use crate::{DetectResult, HtmlExtractor, RuleConfig, RuleOrigin};
// 仅在embedded-rules开启时导入rswappalyzer_rules
#[cfg(feature = "embedded-rules")]
use crate::rswappalyzer_rules;
use crate::RuleLoader;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use rswappalyzer_engine::{CompiledRuleLibrary, RuleIndexer, RuleLibrary, RuleLibraryIndex};
use rustc_hash::FxHashMap;
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
    /// 编译后的规则库（Arc保证多线程共享）
    compiled_lib: Arc<CompiledRuleLibrary>,
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

        Ok(Self {
            compiled_lib: Arc::new(compiled_lib),
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
        Ok(Self {
            compiled_lib: rswappalyzer_rules::EMBEDDED_COMPILED_LIB.clone(),
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
    ) -> Self {
        Self {
            compiled_lib: Arc::new(compiled_lib),
            config,
            rule_index: Some(Arc::new(rule_index)),
        }
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

                Ok(Self {
                    compiled_lib: Arc::new(compiled_lib),
                    config,
                    rule_index: Some(Arc::new(rule_index)),
                })
            }
        }
    }

    /// 创建技术检测器（带详细耗时日志版）
    /// 特性：
    /// 1. 分阶段计时：规则加载/索引构建/规则编译
    /// 2. 正则缓存监控：统计编译前后的正则缓存变化
    /// 3. 详细日志输出：各阶段耗时和关键指标
    /// 参数：config - 规则配置
    /// 返回：检测器实例 | 错误
    pub async fn new_log(config: RuleConfig) -> RswResult<Self> {
        match &config.origin {
            // Embedded模式 - 特性守卫 + 降级处理
            RuleOrigin::Embedded => {
                #[cfg(feature = "embedded-rules")]
                {
                    log::info!("Using rswappalyzer embedded rule library");
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

            // 运行时加载模式（带详细日志）
            RuleOrigin::LocalFile(_) | RuleOrigin::RemoteOfficial | RuleOrigin::RemoteCustom(_) => {
                log::info!("Using runtime rule library, starting loading process");
                let total_start = Instant::now();

                // 1. 加载规则库（优先从缓存加载）
                let rule_loader = RuleLoader::new();
                let rule_lib_load_start = Instant::now();
                let rule_lib = rule_loader.load(&config).await?;
                let rule_lib_load_cost = rule_lib_load_start.elapsed();
                log::info!(
                    "[Stage 1] Rule library loaded | Time: {}ms | Tech rule count: {}",
                    rule_lib_load_cost.as_millis(),
                    rule_lib.core_tech_map.len()
                );

                // 2. 构建RuleLibraryIndex（单独计时）
                let index_build_start = Instant::now();
                let rule_index = RuleLibraryIndex::from_rule_library(&rule_lib)?;
                let index_build_cost = index_build_start.elapsed();
                log::info!(
                    "[Stage 2] RuleLibraryIndex built | Time: {}ms | Rule scope count: {}",
                    index_build_cost.as_millis(),
                    rule_index.rules.len()
                );

                // 3. 编译规则库（带正则缓存监控）
                let compile_lib_start = Instant::now();

                // 监控正则缓存初始状态
                let regex_cache_before = {
                    let cache = rswappalyzer_engine::indexer::matcher::REGEX_CACHE
                        .read()
                        .unwrap();
                    cache.len()
                };
                log::info!(
                    "[Monitor] Regex cache count before compilation: {}",
                    regex_cache_before
                );

                // 执行编译
                let compiled_lib = RuleIndexer::build_compiled_library(
                    &rule_index,
                    Some("data/categories_data.json"),
                )?;

                // 监控正则缓存变化
                let regex_cache_after = {
                    let cache = rswappalyzer_engine::indexer::matcher::REGEX_CACHE
                        .read()
                        .unwrap();
                    cache.len()
                };
                log::info!(
                    "[Monitor] Regex cache count after compilation: {} | New entries: {}",
                    regex_cache_after,
                    regex_cache_after - regex_cache_before
                );

                let compile_lib_cost = compile_lib_start.elapsed();
                log::info!(
                    "[Stage 3] CompiledRuleLibrary built | Time: {}ms | Compiled tech count: {} | Category count: {}",
                    compile_lib_cost.as_millis(),
                    compiled_lib.tech_patterns.len(),
                    compiled_lib.category_map.len()
                );

                // 总耗时统计
                let total_cost = total_start.elapsed();
                log::info!(
                    "[Total] Rule library load + compilation completed | Time: {}ms | Compilation ratio: {:.1}%",
                    total_cost.as_millis(),
                    (compile_lib_cost.as_millis() as f64 / total_cost.as_millis() as f64) * 100.0
                );

                Ok(Self {
                    compiled_lib: Arc::new(compiled_lib),
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

        // 3. 初始化检测结果（FxHashMap高性能哈希表）
        let mut detected = FxHashMap::default();

        // 4. 多维度分析（与detect_with_time完全一致）
        UrlAnalyzer::analyze(&self.compiled_lib, urls, &mut detected);
        HeaderAnalyzer::analyze(&self.compiled_lib, &single_header_map, &mut detected);
        CookieAnalyzer::analyze(&self.compiled_lib, &standard_cookies, &mut detected);

        // 有有效HTML内容时才执行HTML相关分析
        if !html_safe_str.is_empty() {
            HtmlAnalyzer::analyze(&self.compiled_lib, &html_safe_str, &mut detected);
            ScriptAnalyzer::analyze(&self.compiled_lib, &script_src_combined, &mut detected);
            MetaAnalyzer::analyze(&self.compiled_lib, &meta_tags, &mut detected);
        }

        // 5. 应用关联推导规则（与detect_with_time完全一致）
        let imply_map = DetectionUpdater::apply_implies(&self.compiled_lib, &mut detected);

        // 6. 聚合最终结果（预分配容量优化性能）
        let mut technologies = Vec::with_capacity(detected.len());
        for (rule_id, (confidence, version)) in detected {
            if let Some(compiled_tech) = self.compiled_lib.tech_patterns.get(&rule_id) {
                // 构建技术分类列表（与detect_with_time完全一致）
                let categories = compiled_tech
                    .category_ids
                    .iter()
                    .filter_map(|id| self.compiled_lib.category_map.get(id).cloned())
                    .collect();

                // 获取推导来源（与detect_with_time完全一致）
                let implied_by = imply_map.get(&compiled_tech.name).cloned();

                // ========== 修复核心：正确构建Technology对象（支持full-meta特性） ==========
                #[cfg(feature = "full-meta")]
                let (website, description, icon, cpe, saas, pricing) = {
                    let default_meta = TechBasicInfo::default();
                    let tech_meta = self
                        .compiled_lib
                        .tech_meta
                        .get(&rule_id)
                        .unwrap_or(&default_meta);
                    (
                        tech_meta.website.clone(),
                        tech_meta.description.clone(),
                        tech_meta.icon.clone(),
                        tech_meta.cpe.clone(),
                        tech_meta.saas,
                        tech_meta.pricing.clone(),
                    )
                };

                // 构建Technology对象
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

        // 3. 初始化检测结果
        let mut detected = FxHashMap::default();

        // 4.1 URL维度分析 + 耗时统计
        let url_analyze_start = Instant::now();
        UrlAnalyzer::analyze(&self.compiled_lib, urls, &mut detected);
        let url_analyze_cost = url_analyze_start.elapsed();
        println!(
            "[Performance] URL fingerprint analysis completed | Time: {}ms ({:?}) | Detected tech count: {}",
            url_analyze_cost.as_millis(),
            url_analyze_cost,
            detected.len()
        );

        // 4.2 Header维度分析 + 耗时统计
        let header_analyze_start = Instant::now();
        HeaderAnalyzer::analyze(&self.compiled_lib, &single_header_map, &mut detected);
        let header_analyze_cost = header_analyze_start.elapsed();
        println!(
            "[Performance] Header fingerprint analysis completed | Time: {}ms ({:?}) | Detected tech count: {}",
            header_analyze_cost.as_millis(),
            header_analyze_cost,
            detected.len()
        );

        // 4.3 Cookie维度分析 + 耗时统计
        let cookie_analyze_start = Instant::now();
        CookieAnalyzer::analyze(&self.compiled_lib, &standard_cookies, &mut detected);
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
            HtmlAnalyzer::analyze(&self.compiled_lib, &html_safe_str, &mut detected);
            let html_analyze_cost = html_analyze_start.elapsed();
            println!(
                "[Performance] HTML fingerprint analysis completed | Time: {}ms ({:?}) | Detected tech count: {}",
                html_analyze_cost.as_millis(),
                html_analyze_cost,
                detected.len()
            );

            // 4.4.2 Script脚本分析
            let script_analyze_start = Instant::now();
            ScriptAnalyzer::analyze(&self.compiled_lib, &script_src_combined, &mut detected);
            let script_analyze_cost = script_analyze_start.elapsed();
            println!(
                "[Performance] Script fingerprint analysis completed | Time: {}ms ({:?}) | Detected tech count: {}",
                script_analyze_cost.as_millis(),
                script_analyze_cost,
                detected.len()
            );

            // 4.4.3 Meta标签分析
            let meta_analyze_start = Instant::now();
            MetaAnalyzer::analyze(&self.compiled_lib, &meta_tags, &mut detected);
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
        let imply_map = DetectionUpdater::apply_implies(&self.compiled_lib, &mut detected);
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
            if let Some(compiled_tech) = self.compiled_lib.tech_patterns.get(&rule_id) {
                let categories = compiled_tech
                    .category_ids
                    .iter()
                    .filter_map(|id| self.compiled_lib.category_map.get(id).cloned())
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
