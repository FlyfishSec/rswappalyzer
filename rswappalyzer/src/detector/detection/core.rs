//! # 技术栈检测核心模块 (detection::core)
//! 
//! 提供技术栈检测的核心实现逻辑，是整个检测能力的入口层。
//! 核心设计目标：
//! 1. 从原始HTTP数据（头、URL、HTML体）提取标准化检测证据；
//! 2. 通过多维度分析（URL/Header/Cookie/HTML）推导技术栈；
//! 3. 解决Rust生命周期约束问题，保证内存安全与性能平衡；
//! 4. 输出标准化的检测结果，兼容下游消费逻辑。
//! 
//! ## 核心特性
//! - 内联式证据构建：规避临时值生命周期逃逸问题；
//! - 多维度分析：覆盖URL/Header/Cookie/HTML/Script/Meta等维度；
//! - 隐含规则推导：基于已知技术栈推导间接关联的技术；
//! - 高性能设计：使用FxHashMap、强制内联、无冗余内存分配。
//! 
//! ## 核心入口
//! - 函数：`detect` - 核心检测逻辑实现
//! - 方法：`TechDetector::detect` - 检测器实例的便捷封装方法

use super::*;
use crate::detector::TechDetector;
use crate::error::RswResult;
use http::HeaderMap;
use rustc_hash::FxHashMap;
use std::borrow::Cow;
use rswappalyzer_engine::{
    input_evidence::{
        header_evidence::HeaderEvidence,
        html_evidence::HtmlEvidence,
    }
};

/// 技术栈检测核心实现（内联优化版）
/// 
/// 检测能力的核心入口，完成从原始HTTP数据到标准化技术栈检测结果的全流程转换。
/// 为解决临时值生命周期逃逸问题，采用内联式证据构建逻辑设计，避免跨函数引用导致的生命周期错误。
/// 完整流程包含：HTTP头/HTML体证据提取 → 多维度特征分析 → 隐含规则推导 → 结果聚合标准化。
/// 
/// # 设计背景
/// 内联实现的核心诉求是解决Rust的生命周期约束：
/// - 避免临时证据对象跨函数传递时的生命周期逃逸
/// - 消除嵌套元组/临时变量导致的借用检查器报错
/// 
/// # 性能优化
/// - 标记为 `#[inline(always)]`：最大化编译器内联优化，消除函数调用开销
/// - 内联证据构建逻辑：减少临时值的创建与销毁，同时规避生命周期问题
/// 
/// # 参数
/// - `detector`: 技术检测器实例，承载规则库、运行时缓存等核心依赖
/// - `headers`: HTTP响应头映射表，原始头数据输入
/// - `urls`: 待检测的URL列表，用于URL维度的技术特征分析
/// - `body`: HTTP响应体原始字节数据，用于HTML维度的特征提取
/// 
/// # 返回值
/// 成功时返回标准化的检测结果 `DetectResult`（包含检测到的技术栈、隐含推导结果）；
/// 失败时返回 `RswResult` 封装的错误类型，兼容库统一错误处理体系
#[inline]
pub(crate) fn detect(
    detector: &TechDetector,
    headers: &HeaderMap,
    urls: &[&str],
    body: &[u8],
) -> RswResult<DetectResult> {
    // ========== 阶段1：Header证据构建 ==========
    // 转换HTTP头为标准化格式（拆分普通头和Cookie头）
    let (single_header_map, cookie_header_map) = HeaderConverter::convert_all(&headers);
    // 解析Cookie头为标准化Cookie结构
    let standard_cookies = HeaderConverter::parse_to_standard_cookie(&cookie_header_map);
    
    // 构建Header检测证据
    let header_evidence = HeaderEvidence::build(
        &single_header_map,
        &standard_cookies,
        &detector.runtime_lib.get_ac_cache(),
        &detector.runtime_lib.get_compiled_bundle(),
    );

    // ========== 阶段2：HTML证据构建（核心生命周期修复） ==========
    // 将字节流转换为UTF-8字符串（非UTF-8时自动替换为替换字符）
    // let html_str = String::from_utf8_lossy(body);
    // 编码转换
    let html_str = convert_to_utf8(body, headers);

    // HTML输入安全校验 + 提取核心信息
    let (html_safe_str, extract_result) = match HtmlInputGuard::guard(html_str) {
        Some(valid_html) => {
            let html_lc = Cow::Owned(valid_html.to_ascii_lowercase());
            let er = HtmlExtractor::extract(&html_lc);
            (Some(html_lc), Some(er))
        }
        None => (None, None), // 无效HTML时返回空值
    };

    // 构建HTML检测证据
    let html_evidence = if let Some(ref hss) = html_safe_str {
        if let Some(ref er) = extract_result {
            Some(HtmlEvidence::build(
                hss,
                &er.script_src_combined,
                &er.meta_tags,
                &detector.runtime_lib.get_ac_cache(),
                &detector.runtime_lib.get_compiled_bundle(),
            ))
        } else {
            None
        }
    } else {
        None
    };

    // ========== 阶段3：多维度技术分析 ==========
    // 初始化检测结果映射表（规则ID -> (置信度, 版本)）
    let mut detected = FxHashMap::default();
    // URL维度分析
    UrlAnalyzer::analyze(&detector.runtime_lib, urls, &mut detected);
    // Header维度分析
    HeaderAnalyzer::analyze(&detector.runtime_lib, &header_evidence, &mut detected);
    // Cookie维度分析
    CookieAnalyzer::analyze(&detector.runtime_lib, &header_evidence, &mut detected);

    // HTML维度分析（仅当HTML证据有效时执行）
    if let Some(ref evd) = html_evidence {
        HtmlAnalyzer::analyze(&detector.runtime_lib, evd, &mut detected);
        ScriptAnalyzer::analyze(&detector.runtime_lib, evd, &mut detected);
        MetaAnalyzer::analyze(&detector.runtime_lib, evd, &mut detected);
    }

    // ========== 阶段4：关联规则推导 ==========
    // 应用隐含规则，推导间接检测到的技术栈
    let (imply_map, implies_list) =
        DetectionUpdater::apply_implies(&detector.runtime_lib.get_compiled_lib(), &mut detected);

    // ========== 阶段5：结果聚合与标准化 ==========
    // 将原始检测结果转换为标准化的Technology列表
    let technologies = aggregate_detection_results(detector, &detected, &imply_map);

    // 构建最终返回结果
    Ok(DetectResult {
        technologies,
        implies: if implies_list.is_empty() {
            None
        } else {
            Some(implies_list)
        },
    })
}

// /// TechDetector的检测方法便捷封装
// /// 
// /// 作为检测器结构体的实例方法，简化外部调用接口，内部直接转发至核心detect函数。
// /// 标记为 `#[inline(always)]` 以消除封装层的性能开销，保证调用效率与直接调用核心函数一致。
// /// 
// /// # 参数
// /// - `headers`: HTTP响应头映射表
// /// - `urls`: 待检测的URL列表
// /// - `body`: HTTP响应体原始字节数据
// /// 
// /// # 返回值
// /// 与核心`detect`函数一致，返回标准化检测结果或错误
// impl crate::detector::TechDetector {
//     #[inline(always)]
//     pub fn detect(
//         &self,
//         headers: &HeaderMap,
//         urls: &[&str],
//         body: &[u8],
//     ) -> RswResult<DetectResult> {
//         super::super::detection::core::detect(self, headers, urls, body)
//     }
// }