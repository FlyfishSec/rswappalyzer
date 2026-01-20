use crate::error::RswResult;
use http::HeaderMap;

/// 异步全局单例检测接口
/// 特性：自动获取全局检测器实例，执行基础检测
#[inline(always)]
pub async fn detect(headers: &HeaderMap, urls: &[&str], body: &[u8]) -> RswResult<crate::DetectResult> {
    let detector = crate::detector::global::get_global_detector().await?;
    detector.detect(headers, urls, body)
}

/// 异步全局单例检测接口（带耗时统计版）
/// 特性：自动获取全局检测器实例，执行带耗时统计的检测
#[cfg(debug_assertions)]
pub async fn detect_log(
    headers: &HeaderMap,
    urls: &[&str],
    body: &[u8],
) -> RswResult<crate::DetectResult> {
    let detector = crate::detector::global::get_global_detector().await?;
    detector.detect_with_log(headers, urls, body)
}