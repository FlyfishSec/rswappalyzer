//! 技术检测器核心
use crate::DetectResult;
use crate::analyzer::cookie::CookieAnalyzer;
use crate::analyzer::header::HeaderAnalyzer;
use crate::analyzer::html::HtmlAnalyzer;
use crate::analyzer::meta::MetaAnalyzer;
use crate::analyzer::script::ScriptAnalyzer;
use crate::analyzer::url::UrlAnalyzer;
use crate::error::{RswResult, RswappalyzerError};
use crate::rule::core::detect_result::Technology;
use crate::rule::indexer::index_pattern::CompiledRuleLibrary;
use crate::rule::indexer::rule_indexer::{RuleIndexer, RuleLibraryIndex};
use crate::rule::loader::RuleLoader;
use crate::utils::extractor::html_input_guard::HtmlInputGuard;
use crate::utils::{DetectionUpdater, HeaderConverter};
use crate::{HtmlExtractor, RuleConfig, rswappalyzer_rules};
//use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use http::header::{HeaderMap, HeaderName, HeaderValue};
use rustc_hash::FxHashMap;
use std::borrow::Cow;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct TechDetector {
    compiled_lib: Arc<CompiledRuleLibrary>,
    #[allow(dead_code)]
    config: RuleConfig,
    pub rule_index: Option<Arc<RuleLibraryIndex>>,
}

impl TechDetector {
    // 传入纯内存的RuleLibrary
    pub fn with_rules(
        rule_lib: crate::rule::core::RuleLibrary,
        config: RuleConfig,
    ) -> RswResult<Self> {
        let rule_index = RuleLibraryIndex::from_rule_library(&rule_lib)?;
        let compiled_lib = RuleIndexer::build_compiled_library(&rule_index)?;
        Ok(Self {
            compiled_lib: Arc::new(compiled_lib),
            config,
            rule_index: Some(Arc::new(rule_index)),
        })
    }

    // 内置规则构造方法【零配置开箱即用，默认启用】
    #[cfg(feature = "embedded-rules")]
    pub fn with_embedded_rules(config: RuleConfig) -> RswResult<Self> {
        Ok(Self {
            compiled_lib: rswappalyzer_rules::EMBEDDED_COMPILED_LIB.clone(),
            config,
            rule_index: None,
        })
    }

    // 编译后的规则库构造方法
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

    pub async fn new(config: RuleConfig) -> RswResult<Self> {
        match &config.origin {
            // Embedded模式
            crate::RuleOrigin::Embedded => {
                log::info!("使用rswappalyzer内置规则库");
                Self::with_embedded_rules(config)
            }

            // 其他所有运行时加载模式 统一处理
            crate::RuleOrigin::LocalFile(_)
            | crate::RuleOrigin::RemoteOfficial
            | crate::RuleOrigin::RemoteCustom(_) => {
                log::info!("使用运行时规则库，开始加载规则");
                let rule_loader = RuleLoader::new();
                let rule_library = rule_loader.load(&config).await?;
                let rule_index = RuleLibraryIndex::from_rule_library(&rule_library)?;
                let compiled_lib = RuleIndexer::build_compiled_library(&rule_index)?;

                Ok(Self {
                    compiled_lib: Arc::new(compiled_lib),
                    config,
                    rule_index: Some(Arc::new(rule_index)),
                })
            }
        }
    }

    // 检测方法
    #[inline(always)]
    pub fn detect(
        &self,
        headers: &HeaderMap,
        urls: &[&str],
        body: &[u8],
    ) -> RswResult<DetectResult> {
        // 1. Header 提取
        //let header_hashmap = HeaderConverter::to_hashmap(headers);
        //let single_header_map = HeaderConverter::to_single_value(&header_hashmap);
        let (single_header_map, cookie_header_map) = HeaderConverter::convert_all(&headers);
        let standard_cookies = HeaderConverter::parse_to_standard_cookie(&cookie_header_map);

        // 2. HTML 输入守卫 + 提取
        //let html_str = Cow::from(String::from_utf8_lossy(body));
        let html_str = String::from_utf8_lossy(body); // ✅ 零拷贝优化

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
            //None => (Cow::Borrowed(""), Vec::new(), Vec::new()), // 无效 HTML，跳过分析
            None => (
                Cow::Borrowed(""),
                String::new(),
                Vec::with_capacity(0),
            ),
        };

        // 3. 初始化检测结果
        let mut detected = FxHashMap::default();

        // 4. 执行各类分析
        UrlAnalyzer::analyze(&self.compiled_lib, urls, &mut detected);
        HeaderAnalyzer::analyze(&self.compiled_lib, &single_header_map, &mut detected);
        CookieAnalyzer::analyze(&self.compiled_lib, &standard_cookies, &mut detected);

        if !html_safe_str.is_empty() {
            HtmlAnalyzer::analyze(&self.compiled_lib, &html_safe_str, &mut detected);
            ScriptAnalyzer::analyze(&self.compiled_lib, &script_src_combined, &mut detected);
            MetaAnalyzer::analyze(&self.compiled_lib, &meta_tags, &mut detected);
        }

        // 5. 应用关联推导规则，接收多来源映射表
        let imply_map = DetectionUpdater::apply_implies(&self.compiled_lib, &mut detected);

        // 6. 聚合最终结果
        // 预分配Vec容量，优化结果聚合
        let mut technologies = Vec::with_capacity(detected.len());
        for (rule_id, (confidence, version)) in detected {
            if let Some(compiled_tech) = self.compiled_lib.tech_patterns.get(&rule_id) {
                #[cfg(feature = "full-meta")]
                let default_meta = TechBasicInfo::default();
                #[cfg(feature = "full-meta")]
                let tech_meta = self
                    .compiled_lib
                    .tech_meta
                    .get(&rule_id)
                    .unwrap_or(&default_meta);

                let name = compiled_tech.name.clone();
                let categories = compiled_tech
                    .category_ids
                    .iter()
                    .filter_map(|id| self.compiled_lib.category_map.get(id).cloned())
                    .collect();

                let implied_by = imply_map.get(&name).cloned();

                technologies.push(Technology {
                    name,
                    version,
                    categories,
                    confidence,
                    implied_by,
                    #[cfg(feature = "full-meta")]
                    website: tech_meta.website.clone(),
                    #[cfg(feature = "full-meta")]
                    description: tech_meta.description.clone(),
                    #[cfg(feature = "full-meta")]
                    icon: tech_meta.icon.clone(),
                    #[cfg(feature = "full-meta")]
                    cpe: tech_meta.cpe.clone(),
                    #[cfg(feature = "full-meta")]
                    saas: tech_meta.saas,
                    #[cfg(feature = "full-meta")]
                    pricing: tech_meta.pricing.clone(),
                });
            }
        }

        let result = DetectResult {
            technologies,
        };

        Ok(result)
    }

    // 检测方法 - 带全阶段耗时统计+详细日志输出
    #[inline(always)]
    pub fn detect_with_time(
        &self,
        headers: &HeaderMap,
        urls: &[&str],
        body: &[u8],
    ) -> RswResult<DetectResult> {
        use std::time::Instant;
        // 全局总耗时计时器
        let total_start = Instant::now();

        // 1. Header 提取 + 耗时统计
        let header_conv_start = Instant::now();
        let (single_header_map, cookie_header_map) = HeaderConverter::convert_all(&headers);
        let header_conv_cost = header_conv_start.elapsed();
        println!(
            "[耗时统计] Header格式转换完成 | 耗时: {}ms ({:?}) | 单值Header数量: {} | Cookie相关Header数量: {}",
            header_conv_cost.as_millis(),
            header_conv_cost,
            single_header_map.len(),
            cookie_header_map.len()
        );
        let standard_cookies = HeaderConverter::parse_to_standard_cookie(&cookie_header_map);

        // 2. HTML 输入守卫 + 内容提取 + 耗时统计
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
            None => (
                Cow::Borrowed(""),
                String::new(),
                Vec::with_capacity(0), // ✅ 预分配空容量
            ),
        };
        let html_parse_cost = html_parse_start.elapsed();
        println!(
            "[耗时统计] ✅ HTML解析与提取完成 | 耗时: {}ms ({:?}) | 有效HTML: {} | 提取Scripts长度: {} | 提取Meta标签数: {}",
            html_parse_cost.as_millis(),
            html_parse_cost,
            !html_safe_str.is_empty(),
            script_src_combined.len(),
            meta_tags.len()
        );

        // 3. 初始化检测结果 ✅ FxHashMap 完美适配 无编译错误
        let mut detected = FxHashMap::default();

        // ===================== 核心修改：拆分【每个维度独立计时+独立耗时+独立打印】=====================
        // 4.1 URL维度分析 (独立耗时)
        let url_analyze_start = Instant::now();
        UrlAnalyzer::analyze(&self.compiled_lib, urls, &mut detected);
        let url_analyze_cost = url_analyze_start.elapsed();
        println!(
            "[耗时统计] 📌 URL指纹分析完成 | 耗时: {}ms ({:?}) | 当前检测技术数: {}",
            url_analyze_cost.as_millis(),
            url_analyze_cost,
            detected.len()
        );

        // 4.2 Header维度分析 (独立耗时)
        let header_analyze_start = Instant::now();
        HeaderAnalyzer::analyze(&self.compiled_lib, &single_header_map, &mut detected);
        let header_analyze_cost = header_analyze_start.elapsed();
        println!(
            "[耗时统计] 📌 Header指纹分析完成 | 耗时: {}ms ({:?}) | 当前检测技术数: {}",
            header_analyze_cost.as_millis(),
            header_analyze_cost,
            detected.len()
        );

        // 4.3 Cookie维度分析 (独立耗时)
        let cookie_analyze_start = Instant::now();
        CookieAnalyzer::analyze(&self.compiled_lib, &standard_cookies, &mut detected);
        let cookie_analyze_cost = cookie_analyze_start.elapsed();
        println!(
            "[耗时统计] 📌 Cookie指纹分析完成 | 耗时: {}ms ({:?}) | 当前检测技术数: {}",
            cookie_analyze_cost.as_millis(),
            cookie_analyze_cost,
            detected.len()
        );

        // 4.4 HTML相关维度分析 (独立拆分，有HTML内容才执行)
        if !html_safe_str.is_empty() {
            // 4.4.1 HTML文本维度分析 (独立耗时)
            let html_analyze_start = Instant::now();
            HtmlAnalyzer::analyze(&self.compiled_lib, &html_safe_str, &mut detected);
            let html_analyze_cost = html_analyze_start.elapsed();
            println!(
                "[耗时统计] 📌 HTML指纹分析完成 | 耗时: {}ms ({:?}) | 当前检测技术数: {}",
                html_analyze_cost.as_millis(),
                html_analyze_cost,
                detected.len()
            );

            // 4.4.2 Script脚本维度分析 (独立耗时)
            let script_analyze_start = Instant::now();
            ScriptAnalyzer::analyze(&self.compiled_lib, &script_src_combined, &mut detected);
            let script_analyze_cost = script_analyze_start.elapsed();
            println!(
                "[耗时统计] 📌 Script指纹分析完成 | 耗时: {}ms ({:?}) | 当前检测技术数: {}",
                script_analyze_cost.as_millis(),
                script_analyze_cost,
                detected.len()
            );

            // 4.4.3 Meta标签维度分析 (独立耗时)
            let meta_analyze_start = Instant::now();
            MetaAnalyzer::analyze(&self.compiled_lib, &meta_tags, &mut detected);
            let meta_analyze_cost = meta_analyze_start.elapsed();
            println!(
                "[耗时统计] 📌 Meta指纹分析完成 | 耗时: {}ms ({:?}) | 当前检测技术数: {}",
                meta_analyze_cost.as_millis(),
                meta_analyze_cost,
                detected.len()
            );
        } else {
            println!("[耗时统计] ⚠️  无效HTML内容，跳过HTML/Script/Meta相关分析");
        }

        // 5. 应用关联推导规则 + 独立耗时统计
        let imply_start = Instant::now();
        let imply_map = DetectionUpdater::apply_implies(&self.compiled_lib, &mut detected);
        let imply_cost = imply_start.elapsed();
        println!(
            "[耗时统计] ✅ 关联规则推导完成 | 耗时: {}ms ({:?}) | 推导新增技术数: {} | 推导后总技术数: {}",
            imply_cost.as_millis(),
            imply_cost,
            imply_map.len(),
            detected.len()
        );

        // 6. 聚合最终结果 + 独立耗时统计
        let aggregate_start = Instant::now();
        let mut technologies = Vec::with_capacity(detected.len());
        for (rule_id, (confidence, version)) in detected {
            if let Some(compiled_tech) = self.compiled_lib.tech_patterns.get(&rule_id) {
                #[cfg(feature = "full-meta")]
                let default_meta = TechBasicInfo::default();
                #[cfg(feature = "full-meta")]
                let tech_meta = self
                    .compiled_lib
                    .tech_meta
                    .get(&rule_id)
                    .unwrap_or(&default_meta);

                let name = compiled_tech.name.clone();
                let categories = compiled_tech
                    .category_ids
                    .iter()
                    .filter_map(|id| self.compiled_lib.category_map.get(id).cloned())
                    .collect();

                let implied_by = imply_map.get(&name).cloned();
        
                technologies.push(Technology {
                    name,
                    version,
                    categories,
                    confidence,
                    implied_by,
                    #[cfg(feature = "full-meta")]
                    website: tech_meta.website.clone(),
                    #[cfg(feature = "full-meta")]
                    description: tech_meta.description.clone(),
                    #[cfg(feature = "full-meta")]
                    icon: tech_meta.icon.clone(),
                    #[cfg(feature = "full-meta")]
                    cpe: tech_meta.cpe.clone(),
                    #[cfg(feature = "full-meta")]
                    saas: tech_meta.saas,
                    #[cfg(feature = "full-meta")]
                    pricing: tech_meta.pricing.clone(),
                });
            }
        }

        let aggregate_cost = aggregate_start.elapsed();
        println!(
            "[耗时统计] ✅ 最终结果聚合完成 | 耗时: {}ms ({:?}) | 最终检测技术栈总数: {}",
            aggregate_cost.as_millis(),
            aggregate_cost,
            technologies.len()
        );

        // 计算全局总耗时 & 最终汇总打印 (纯println，无任何日志依赖)
        let total_cost = total_start.elapsed();
        println!("======================================================================");
        println!(
            "[检测完成] ✅ 全流程执行完毕 | 整体总耗时: {}ms ({:?}) | 最终识别技术数: {} | 关联推导技术数: {}",
            total_cost.as_millis(),
            total_cost,
            technologies.len(),
            imply_map.len()
        );
        println!("======================================================================");

        let result = DetectResult {
            technologies,
        };

        Ok(result)
    }

    #[inline(always)]
    pub fn detect_with_hashmap(
        &self,
        headers: &FxHashMap<String, Vec<String>>,
        urls: &[&str],
        body: &[u8],
    ) -> RswResult<DetectResult> {
        let single_header_map = HeaderConverter::to_single_value(headers);
        let mut header_map = HeaderMap::new();
        for (key, value) in single_header_map {
            let header_name = HeaderName::from_bytes(key.as_bytes()).map_err(|e| {
                RswappalyzerError::InvalidInput(format!("无效Header名称：{}，错误：{}", key, e))
            })?;
            let header_value = HeaderValue::from_str(&value).map_err(|e| {
                RswappalyzerError::InvalidInput(format!("无效Header值：{}，错误：{}", value, e))
            })?;
            header_map.append(header_name, header_value);
        }
        self.detect(&header_map, urls, body)
    }
}

/// async 全局单例调用
#[inline(always)]
pub async fn detect(headers: &HeaderMap, urls: &[&str], body: &[u8]) -> RswResult<DetectResult> {
    let detector = super::global::get_global_detector().await?;
    detector.detect(headers, urls, body)
}

#[inline(always)]
pub async fn detect_with_time(
    headers: &HeaderMap,
    urls: &[&str],
    body: &[u8],
) -> RswResult<DetectResult> {
    let detector = super::global::get_global_detector().await?;
    detector.detect_with_time(headers, urls, body)
}
