//! 检测器核心：整合各类分析器，输出检测结果
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use super::analyzer::{UrlAnalyzer, HeaderAnalyzer, HtmlAnalyzer, ScriptAnalyzer, MetaAnalyzer};
use crate::TechRule;
use crate::compiler::{CompiledRuleLibrary, RuleCompiler};
use crate::rule::RuleLoader;
use crate::extractor::HtmlExtractor;
use crate::utils::{HeaderConverter, DetectionUpdater};
use crate::error::{RswResult, RswappalyzerError};
use crate::config::GlobalConfig;
use crate::rule::model::{Technology, TechnologyLite};

/// 技术检测器
#[derive(Debug, Clone)]
pub struct TechDetector {
    compiled_lib: Arc<CompiledRuleLibrary>,
    config: GlobalConfig,
    raw_tech_rules: Arc<HashMap<String, TechRule>>,
}

impl TechDetector {
    /// 创建检测器
    pub async fn new(config: GlobalConfig) -> RswResult<Self> {
        // 1. 加载原始规则库
        let rule_lib = RuleLoader::load(&config).await?;
        let raw_tech_rules = Arc::new(rule_lib.tech_rules.clone());

        // 2. 编译规则库
        let compiled_lib = RuleCompiler::compile(&rule_lib)?;

        Ok(Self {
            compiled_lib: Arc::new(compiled_lib),
            config,
            raw_tech_rules,
        })
    }

    /// 核心检测接口（HeaderMap + URL + Body）
    pub fn detect(
        &self,
        headers: &HeaderMap,
        urls: &[&str],
        body: &[u8],
    ) -> RswResult<Vec<Technology>> {
        // 1. 转换Header格式
        let header_hashmap = HeaderConverter::to_hashmap(headers);
        let single_header_map = HeaderConverter::to_single_value(&header_hashmap);

        // 2. 提取HTML内容和标签
        let html_str = Cow::from(String::from_utf8_lossy(body));
        let html_extractor = HtmlExtractor::new();
        let html_result = html_extractor.extract(&html_str);
        let script_srcs = html_result.get_script_srcs();
        let meta_tags = html_result.get_meta_tags();

        // 3. 初始化检测结果
        let mut detected = HashMap::new();

        // 4. 执行各类分析
        UrlAnalyzer::analyze(&self.compiled_lib, urls, &mut detected);
        HeaderAnalyzer::analyze(&self.compiled_lib, &single_header_map, &mut detected);
        HtmlAnalyzer::analyze(&self.compiled_lib, &html_str, &mut detected);
        ScriptAnalyzer::analyze(&self.compiled_lib, &script_srcs, &mut detected);
        MetaAnalyzer::analyze(&self.compiled_lib, &meta_tags, &mut detected);

        // 5. 应用关联推导规则
        DetectionUpdater::apply_implies(&self.raw_tech_rules, &mut detected);

        // 6. 转换为最终结果
        let mut technologies = Vec::new();
        for (tech_name, (confidence, version)) in detected {
            let compiled_tech = self.compiled_lib.tech_patterns.get(&tech_name).unwrap();

            // 转换分类ID为分类名称
            let categories = compiled_tech.category_ids.iter()
                .filter_map(|cat_id| self.compiled_lib.category_map.get(cat_id).cloned())
                .collect();

            technologies.push(Technology {
                name: tech_name,
                confidence,
                version,
                categories,
                website: compiled_tech.website.clone(),
                description: compiled_tech.description.clone(),
                icon: compiled_tech.icon.clone(),
                cpe: compiled_tech.cpe.clone(),
                saas: compiled_tech.saas,
                pricing: compiled_tech.pricing.clone(),
            });
        }

        Ok(technologies)
    }

    /// 检测接口（HashMap<String, Vec<String>> 头）
    pub fn detect_with_hashmap(
        &self,
        headers: &HashMap<String, Vec<String>>,
        urls: &[&str],
        body: &[u8],
    ) -> RswResult<Vec<Technology>> {
        let single_header_map = HeaderConverter::to_single_value(headers);
        let mut header_map = HeaderMap::new();
        for (key, value) in single_header_map {
            let header_name = HeaderName::from_bytes(key.as_bytes())
                .map_err(|e| RswappalyzerError::InvalidInput(format!("无效Header名称：{}，错误：{}", key, e)))?;
            let header_value = HeaderValue::from_str(&value)
                .map_err(|e| RswappalyzerError::InvalidInput(format!("无效Header值：{}，错误：{}", value, e)))?;
            header_map.append(header_name, header_value);
        }
        self.detect(&header_map, urls, body)
    }

    /// 精简版检测接口
    pub fn detect_lite(
        &self,
        headers: &HeaderMap,
        urls: &[&str],
        body: &[u8],
    ) -> RswResult<Vec<TechnologyLite>> {
        let full_techs = self.detect(headers, urls, body)?;
        Ok(full_techs.into_iter().map(TechnologyLite::from).collect())
    }

    /// 精简版检测接口（HashMap头）
    pub fn detect_lite_with_hashmap(
        &self,
        headers: &HashMap<String, Vec<String>>,
        urls: &[&str],
        body: &[u8],
    ) -> RswResult<Vec<TechnologyLite>> {
        let full_techs = self.detect_with_hashmap(headers, urls, body)?;
        Ok(full_techs.into_iter().map(TechnologyLite::from).collect())
    }

    /// 兼容带Cookies的检测接口（Cookies暂未使用）
    pub fn detect_with_cookies(
        &self,
        headers: &HeaderMap,
        _cookies: &[&str],
        body: &[u8],
    ) -> RswResult<Vec<Technology>> {
        self.detect(headers, &[], body)
    }

    /// 精简版兼容带Cookies的检测接口
    pub fn detect_lite_with_cookies(
        &self,
        headers: &HeaderMap,
        _cookies: &[&str],
        body: &[u8],
    ) -> RswResult<Vec<TechnologyLite>> {
        self.detect_lite(headers, &[], body)
    }
}

// 对外暴露的简化接口（兼容原有调用方式）
pub fn header_map_to_hashmap(headers: &HeaderMap) -> HashMap<String, Vec<String>> {
    HeaderConverter::to_hashmap(headers)
}

pub fn detect_technologies_wappalyzer(
    headers: &HeaderMap,
    urls: &[&str],
    body: &[u8],
) -> RswResult<Vec<Technology>> {
    let detector = super::global::get_global_detector()?;
    detector.detect(headers, urls, body)
}

pub fn detect_technologies_wappalyzer_hashmap(
    headers: &HashMap<String, Vec<String>>,
    urls: &[&str],
    body: &[u8],
) -> RswResult<Vec<Technology>> {
    let detector = super::global::get_global_detector()?;
    detector.detect_with_hashmap(headers, urls, body)
}

pub fn detect_technologies_wappalyzer_lite(
    headers: &HeaderMap,
    urls: &[&str],
    body: &[u8],
) -> RswResult<Vec<TechnologyLite>> {
    let detector = super::global::get_global_detector()?;
    detector.detect_lite(headers, urls, body)
}

pub fn detect_technologies_wappalyzer_lite_hashmap(
    headers: &HashMap<String, Vec<String>>,
    urls: &[&str],
    body: &[u8],
) -> RswResult<Vec<TechnologyLite>> {
    let detector = super::global::get_global_detector()?;
    detector.detect_lite_with_hashmap(headers, urls, body)
}

pub fn detect_technologies_wappalyzer_with_cookies(
    headers: &HeaderMap,
    cookies: &[&str],
    body: &[u8],
) -> RswResult<Vec<Technology>> {
    let detector = super::global::get_global_detector()?;
    detector.detect_with_cookies(headers, cookies, body)
}

pub fn detect_technologies_wappalyzer_lite_with_cookies(
    headers: &HeaderMap,
    cookies: &[&str],
    body: &[u8],
) -> RswResult<Vec<TechnologyLite>> {
    let detector = super::global::get_global_detector()?;
    detector.detect_lite_with_cookies(headers, cookies, body)
}