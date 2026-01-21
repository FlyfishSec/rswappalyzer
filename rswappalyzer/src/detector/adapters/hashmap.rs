use crate::{DetectResult, HeaderConverter};
use crate::detector::TechDetector;
use crate::error::RswResult;
use http::header::{HeaderName, HeaderValue};
use http::HeaderMap;
use rustc_hash::FxHashMap;

/// 核心检测方法（HashMap输入版）
/// 适用场景：Header以HashMap形式传入（非标准HeaderMap）
#[inline(always)]
pub fn detect_with_hashmap(
    detector: &TechDetector,
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
            crate::error::RswError::InvalidInput(format!(
                "Invalid header name: {}, error: {}",
                key, e
            ))
        })?;
        let header_value = HeaderValue::from_str(&value).map_err(|e| {
            crate::error::RswError::InvalidInput(format!(
                "Invalid header value: {}, error: {}",
                value, e
            ))
        })?;
        header_map.append(header_name, header_value);
    }

    // 调用基础检测方法
    detector.detect(&header_map, urls, body)
}

// 为TechDetector实现detect_with_hashmap方法
impl TechDetector {
    #[inline(always)]
    pub fn detect_with_hashmap(
        &self,
        headers: &FxHashMap<String, Vec<String>>,
        urls: &[&str],
        body: &[u8],
    ) -> RswResult<DetectResult> {
        detect_with_hashmap(self, headers, urls, body)
    }
}