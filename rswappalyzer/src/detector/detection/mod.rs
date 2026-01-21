//! 技术检测核心逻辑模块
//! 
//! 该模块提供技术栈检测的核心实现，包含基础检测逻辑和带日志的调试版本，
//! 并封装了检测结果聚合、元数据填充等辅助能力。

// 核心检测逻辑实现模块
pub mod core;
// // 导出核心检测函数供外部使用
// pub use self::core::detect;

// 调试模式下导出带日志的检测函数（仅 debug 编译时生效）
#[cfg(debug_assertions)]
pub use self::with_log::detect_with_log;
#[cfg(debug_assertions)]
mod with_log;

// 引入依赖模块/类型
use crate::detector::TechDetector;
use crate::utils::{DetectionUpdater, HeaderConverter};
use crate::{DetectResult, HtmlExtractor, Technology};
use crate::utils::extractor::html_input_guard::HtmlInputGuard;
use crate::analyzer::{
    cookie::CookieAnalyzer, header::HeaderAnalyzer, html::HtmlAnalyzer, meta::MetaAnalyzer,
    script::ScriptAnalyzer, url::UrlAnalyzer,
};
use rustc_hash::FxHashMap;

/// 聚合检测结果为标准化的 Technology 列表
/// 
/// 将底层检测出的原始规则匹配结果（规则ID-置信度-版本）转换为对外暴露的
/// 标准化 Technology 结构体列表，并补充分类、隐含依赖等元信息。
/// 
/// # 参数
/// - `detector`: 技术检测器实例，用于获取规则库和元数据
/// - `detected`: 原始检测结果映射（规则ID -> (置信度, 版本)）
/// - `imply_map`: 技术隐含依赖映射（技术名称 -> 隐含的其他技术列表）
/// 
/// # 返回值
/// 标准化的 Technology 列表，包含名称、版本、分类、置信度等完整信息
pub(crate) fn aggregate_detection_results(
    detector: &TechDetector,
    detected: &FxHashMap<String, (u8, Option<String>)>,
    imply_map: &FxHashMap<String, Vec<String>>,
) -> Vec<Technology> {
    // 预分配容量以优化性能（基于原始检测结果数量）
    let mut technologies = Vec::with_capacity(detected.len());

    // 遍历所有原始检测结果，转换为标准化结构
    for (rule_id, (confidence, version)) in detected {
        // 跳过未找到对应规则定义的无效结果
        let Some(compiled_tech) = detector.runtime_lib.compiled_lib().tech_patterns.get(rule_id) else {
            continue;
        };

        // 转换分类ID为分类名称列表
        let categories = compiled_tech
            .category_ids
            .iter()
            .filter_map(|id| detector.runtime_lib.compiled_lib().category_map.get(id).cloned())
            .collect();

        // 获取当前技术隐含的其他技术依赖
        let implied_by = imply_map.get(&compiled_tech.name).cloned();

        // 构建标准化 Technology 实例（兼容 full-meta 特性开关）
        let tech = Technology {
            name: compiled_tech.name.clone(),
            version: version.clone(),
            categories,
            confidence: *confidence,
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

        // 若启用 full-meta 特性，补充技术元数据
        #[cfg(feature = "full-meta")]
        fill_tech_meta(detector, rule_id, &tech);

        technologies.push(tech);
    }

    technologies
}

/// 为 Technology 补充完整元数据（仅启用 full-meta 特性时生效）
/// 
/// 从规则库中读取技术的扩展元信息（官网、描述、图标等），并填充到 Technology 结构体中。
/// 若未找到对应元数据，则使用默认值。
/// 
/// # 参数
/// - `detector`: 技术检测器实例，用于获取元数据仓库
/// - `rule_id`: 检测规则ID，关联对应的元数据
/// - `tech`: 需要填充元数据的 Technology 实例（当前仅获取元数据，未完成赋值逻辑）
#[cfg(feature = "full-meta")]
fn fill_tech_meta(detector: &TechDetector, rule_id: &str, tech: &Technology) {
    // 定义默认元数据（避免空指针）
    let default_meta = crate::utils::TechBasicInfo::default();
    // 从规则库获取元数据（未找到则使用默认值）
    let tech_meta = detector
        .runtime_lib
        .compiled_lib()
        .tech_meta
        .get(rule_id)
        .unwrap_or(&default_meta);
}