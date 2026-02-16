//! # 技术栈检测核心模块（带性能日志） (detection::with_log)
//!
//! 提供带全阶段耗时统计和详细日志输出的技术栈检测实现，是核心检测逻辑的日志增强版。
//! 核心设计目标：
//! 1. 完全兼容基础检测逻辑的功能输出；
//! 2. 对检测全流程进行精细化性能打点，输出各阶段耗时与关键指标；
//! 3. 保留内联式证据构建逻辑，解决Rust生命周期约束问题；
//! 4. 输出结构化性能日志，便于性能分析与问题定位。
//!
//! ## 核心特性
//! - 全流程性能打点：覆盖Header/HTML处理、多维度分析、规则推导、结果聚合等所有阶段；
//! - 结构化日志输出：包含阶段耗时、关键指标（如检测到的技术数、HTML长度等）；
//! - 兼容基础检测逻辑：输出格式与基础detect函数完全一致；
//! - 内联证据构建：规避生命周期逃逸问题，保证内存安全。
//!
//! ## 核心入口
//! - 函数：`detect_with_log` - 带日志的核心检测逻辑实现
//! - 方法：`TechDetector::detect_with_log` - 检测器实例的便捷封装方法

use super::*;
use crate::detector::TechDetector;
use crate::error::RswResult;
use http::HeaderMap;
use rswappalyzer_engine::input_evidence::header_evidence::HeaderEvidence;
use rswappalyzer_engine::input_evidence::html_evidence::HtmlEvidence;
use rustc_hash::FxHashMap;
use std::borrow::Cow;
use std::time::{Duration, Instant};

/// 核心检测方法（带全阶段耗时统计+详细日志）
///
/// 基础检测逻辑的日志增强版，在完成技术栈检测的同时，对全流程各阶段进行性能打点，
/// 输出结构化的性能日志（包含阶段耗时、关键指标），便于性能分析与问题定位。
/// 核心逻辑与基础detect函数完全一致，保留内联式证据构建以解决生命周期逃逸问题。
///
/// # 设计背景
/// 内联证据构建逻辑的核心诉求是解决Rust生命周期约束：
/// - 避免临时证据对象跨函数传递时的生命周期逃逸；
/// - 消除嵌套元组/临时变量导致的借用检查器报错。
///
/// # 性能特性
/// - 标记为 `#[inline(always)]`：最大化编译器内联优化，减少函数调用开销；
/// - 精细化性能打点：对每个核心阶段单独计时，无全局锁/大粒度锁，性能损耗可控；
/// - 结构化日志输出：仅增加IO日志开销，不影响核心检测逻辑性能。
///
/// # 参数
/// - `detector`: 技术检测器实例，承载规则库、运行时缓存等核心依赖；
/// - `headers`: HTTP响应头映射表，原始头数据输入；
/// - `urls`: 待检测的URL列表，用于URL维度的技术特征分析；
/// - `body`: HTTP响应体原始字节数据，用于HTML维度的特征提取。
///
/// # 返回值
/// 成功时返回标准化的检测结果 `DetectResult`（包含检测到的技术栈、隐含推导结果）；
/// 失败时返回 `RswResult` 封装的错误类型，兼容库统一错误处理体系。
#[inline]
pub fn detect_with_log(
    detector: &TechDetector,
    headers: &HeaderMap,
    urls: &[&str],
    body: &[u8],
) -> RswResult<DetectResult> {
    /// 打印性能日志的通用函数
    ///
    /// 标准化性能日志输出格式，统一各阶段日志的展示样式，包含阶段名称、耗时、额外信息。
    ///
    /// # 参数
    /// - `phase`: 阶段名称（如"Header AC automaton scan completed"）；
    /// - `cost`: 该阶段耗时；
    /// - `extra_info`: 额外指标信息（如Header数量、检测到的技术数等）。
    fn print_perf_log(phase: &str, cost: Duration, extra_info: &str) {
        println!(
            "[Performance] {} | Time: {}ms ({:?}) {}",
            phase,
            cost.as_millis() as u64,
            cost,
            extra_info
        );
    }

    /// 执行分析并打印日志的通用函数
    ///
    /// 封装"计时-执行分析函数-打印日志"的通用逻辑，减少代码冗余，保证各分析阶段日志格式统一。
    ///
    /// # 泛型参数
    /// - `F`: 分析函数类型，需满足FnMut() -> ()约束，无返回值。
    ///
    /// # 参数
    /// - `phase`: 阶段名称；
    /// - `analysis_fn`: 待执行的分析函数（如URLAnalyzer::analyze）。
    ///
    /// # 返回值
    /// 该分析阶段的耗时。
    fn run_analysis<F>(phase: &str, mut analysis_fn: F) -> Duration
    where
        F: FnMut() -> (),
    {
        let start = Instant::now();
        analysis_fn();
        let cost = start.elapsed();
        print_perf_log(phase, cost, "");
        cost
    }

    // 1. 初始化与总计时
    let total_start = Instant::now();

    // 2. Header处理阶段
    let (single_header_map, cookie_header_map) = HeaderConverter::convert_all(&headers);
    let standard_cookies = HeaderConverter::parse_to_standard_cookie(&cookie_header_map);

    let header_ac_scan_cost = run_analysis("Header AC automaton scan completed", || {});
    let header_evidence = HeaderEvidence::build(
        &single_header_map,
        &standard_cookies,
        &detector.runtime_lib.get_ac_cache(),
        &detector.runtime_lib.get_compiled_bundle(),
    );
    print_perf_log(
        "Header AC automaton scan completed",
        header_ac_scan_cost,
        &format!(
            "| Header count: {} | Cookie count: {}",
            single_header_map.len(),
            standard_cookies.len()
        ),
    );

    // 3. HTML处理阶段
    let (html_safe_str, script_src_combined, meta_tags, html_parse_cost, cost_lc) =
        process_html(detector, body, headers);
    print_perf_log(
        "HTML parsing & extraction completed",
        html_parse_cost,
        &format!(
            "| Valid HTML: {} | Script src length: {} | Meta tag count: {} | lowercase: {:?}",
            !html_safe_str.is_empty(),
            script_src_combined.len(),
            meta_tags.len(),
            cost_lc
        ),
    );

    // 3.1 HTML AC自动机扫描
    let html_evidence = if !html_safe_str.is_empty() {
        let mut html_evd = None;
        let html_ac_scan_cost = run_analysis("HTML AC automaton scan completed", || {
            html_evd = Some(HtmlEvidence::build(
                &html_safe_str,
                &script_src_combined,
                &meta_tags,
                &detector.runtime_lib.get_ac_cache(),
                &detector.runtime_lib.get_compiled_bundle(),
            ));

            println!("[PERF] AC扫描+转换完成 | HTML长度: {}", html_safe_str.len());
        });
        print_perf_log(
            "HTML AC automaton scan completed",
            html_ac_scan_cost,
            &format!("| HTML length: {}", html_safe_str.len()),
        );
        html_evd
    } else {
        println!("[Performance] No valid HTML content, skip HTML AC automaton scan");
        None
    };

    // 4. 多维度检测分析阶段
    let mut detected = FxHashMap::default();

    let url_analyze_cost = run_analysis("URL fingerprint analysis completed", || {
        UrlAnalyzer::analyze(&detector.runtime_lib, urls, &mut detected)
    });
    print_perf_log(
        "URL fingerprint analysis completed",
        url_analyze_cost,
        &format!("| Detected tech count: {}", detected.len()),
    );

    let header_analyze_cost = run_analysis("Header fingerprint analysis completed", || {
        HeaderAnalyzer::analyze(&detector.runtime_lib, &header_evidence, &mut detected);
        if single_header_map.is_empty() && standard_cookies.is_empty() {
            println!("[Performance] Header evidence is empty, no tech detected from header");
        }
    });
    print_perf_log(
        "Header fingerprint analysis completed",
        header_analyze_cost,
        &format!("| Detected tech count: {}", detected.len()),
    );

    let cookie_analyze_cost = run_analysis("Cookie fingerprint analysis completed", || {
        CookieAnalyzer::analyze(&detector.runtime_lib, &header_evidence, &mut detected);
        if standard_cookies.is_empty() {
            println!("[Performance] No cookie evidence, skip Cookie fingerprint analysis");
        }
    });
    print_perf_log(
        "Cookie fingerprint analysis completed",
        cookie_analyze_cost,
        &format!("| Detected tech count: {}", detected.len()),
    );

    if let Some(ref evd) = html_evidence {
        let _html_analyze_cost = run_analysis("HTML fingerprint analysis completed", || {
            HtmlAnalyzer::analyze(&detector.runtime_lib, evd, &mut detected)
        });
        let _script_analyze_cost = run_analysis("Script fingerprint analysis completed", || {
            ScriptAnalyzer::analyze(&detector.runtime_lib, evd, &mut detected)
        });
        let _meta_analyze_cost = run_analysis("Meta fingerprint analysis completed", || {
            MetaAnalyzer::analyze(&detector.runtime_lib, evd, &mut detected)
        });
    } else {
        println!("[Performance] No valid HTML content, skip HTML/Script/Meta analysis");
    }

    // 5. 关联规则推导阶段
    let imply_start = Instant::now();
    let (imply_map, implies_list) =
        DetectionUpdater::apply_implies(&detector.runtime_lib.get_compiled_lib(), &mut detected);
    let imply_cost = imply_start.elapsed();
    println!(
        "[Performance] Implication rule application completed | Time: {}ms ({:?}) | Implied tech count: {} | Total detected tech count: {}",
        imply_cost.as_millis(),
        imply_cost,
        imply_map.len(),
        detected.len()
    );

    // 6. 结果聚合阶段
    let aggregate_start = Instant::now();
    let technologies = aggregate_detection_results(detector, &detected, &imply_map);
    let aggregate_cost = aggregate_start.elapsed();
    println!(
        "[Performance] Result aggregation completed | Time: {}ms ({:?}) | Final detected tech count: {}",
        aggregate_cost.as_millis(),
        aggregate_cost,
        technologies.len()
    );

    // 7. 总耗时统计
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

    Ok(DetectResult {
        technologies,
        implies: if implies_list.is_empty() {
            None
        } else {
            Some(implies_list)
        },
    })
}

/// 处理HTML解析与提取的辅助方法
///
/// 封装HTML字节流的解析、安全校验、核心特征提取逻辑，返回标准化的HTML数据和各步骤耗时。
/// 核心逻辑包含：UTF-8转换、安全校验、小写转换、Script/Meta特征提取，同时统计关键步骤耗时。
///
/// # 生命周期说明
/// - 泛型生命周期`'a`：绑定输入body的生命周期，确保返回的Cow<str>不发生生命周期逃逸；
/// - 返回值使用Cow<str>：避免不必要的内存拷贝，提升性能。
///
/// # 参数
/// - `_detector`: 技术检测器实例（预留参数，便于后续扩展）；
/// - `body`: HTTP响应体原始字节数据。
///
/// # 返回值
/// 元组包含以下内容：
/// 1. `Cow<'a, str>`: 安全校验后的HTML字符串（小写）；
/// 2. `String`: 提取的Script src合并字符串；
/// 3. `Vec<(String, String)>`: 提取的Meta标签列表；
/// 4. `Duration`: HTML处理总耗时；
/// 5. `Duration`: 字符串小写转换耗时。
fn process_html<'a>(
    _detector: &'a TechDetector,
    body: &'a [u8],
    headers: &HeaderMap,
) -> (
    Cow<'a, str>,
    String,
    Vec<(String, String)>,
    Duration,
    Duration,
) {
    let start = Instant::now();
    //let html_str = String::from_utf8_lossy(body);
    // 编码转换
    let html_str = convert_to_utf8(body, headers);

    let mut cost_lc = Duration::ZERO;

    let (html_safe_str, script_src_combined, meta_tags) = match HtmlInputGuard::guard(html_str) {
        Some(valid_html) => {
            let t_lc_start = Instant::now();
            let html_lc = Cow::Owned(valid_html.to_ascii_lowercase());
            cost_lc = t_lc_start.elapsed();
            let html_result = HtmlExtractor::extract(&html_lc);
            (
                html_lc,
                html_result.script_src_combined,
                html_result.meta_tags,
            )
        }
        None => (Cow::Borrowed(""), String::new(), Vec::with_capacity(0)),
    };

    let total_cost = start.elapsed();
    (
        html_safe_str,
        script_src_combined,
        meta_tags,
        total_cost,
        cost_lc,
    )
}

// /// TechDetector的detect_with_log方法封装
// ///
// /// 作为检测器结构体的实例方法，简化带日志检测功能的外部调用接口，
// /// 内部直接转发至核心detect_with_log函数，保证调用体验与基础detect方法一致。
// /// 标记为 `#[inline(always)]` 以消除封装层的性能开销，保证调用效率。
// ///
// /// # 参数
// /// - `headers`: HTTP响应头映射表；
// /// - `urls`: 待检测的URL列表；
// /// - `body`: HTTP响应体原始字节数据。
// ///
// /// # 返回值
// /// 与核心`detect_with_log`函数一致，返回带日志的标准化检测结果或错误。
// impl crate::detector::TechDetector {
//     #[inline(always)]
//     pub fn detect_with_log(
//         &self,
//         headers: &HeaderMap,
//         urls: &[&str],
//         body: &[u8],
//     ) -> RswResult<DetectResult> {
//         super::super::detection::with_log::detect_with_log(self, headers, urls, body)
//     }
// }
