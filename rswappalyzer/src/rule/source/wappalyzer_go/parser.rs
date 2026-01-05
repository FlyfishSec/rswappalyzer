//! Wappalyzer 规则解析器
//! 实现通用解析器 Trait，专门解析 Wappalyzer 格式规则（仅负责解析原始结构）

use serde_json::Value;
use async_trait::async_trait;
use crate::RuleSourceParser;
use crate::error::{RswResult};
use crate::rule::RuleFileType;
use crate::rule::source::wappalyzer_go::original::WappalyzerOriginalRuleLibrary;


/// Wappalyzer Go 规则解析器
#[derive(Debug, Clone, Default)]
pub struct WappalyzerGoParser;

#[async_trait]
impl RuleSourceParser<WappalyzerOriginalRuleLibrary> for WappalyzerGoParser {
    fn rule_file_type(&self) -> RuleFileType {
        RuleFileType::WappalyzerGoJson
    }

    /// 从 JSON 字符串解析 Wappalyzer 原始规则库
    fn parse_original_from_str(&self, content: &str) -> RswResult<WappalyzerOriginalRuleLibrary> {
        Ok(serde_json::from_str(content)?)
    }

    /// 从字节流解析 Wappalyzer 原始规则库
    fn parse_original_from_bytes(&self, bytes: &[u8]) -> RswResult<WappalyzerOriginalRuleLibrary> {
        Ok(serde_json::from_slice(bytes)?)
    }

    /// 从 HTTP 响应解析 Wappalyzer 原始规则库
    #[cfg(feature = "remote-loader")]
    async fn parse_original_from_response(&self, response: reqwest::Response) -> RswResult<WappalyzerOriginalRuleLibrary> {
        // 先保存 status（Copy 类型）
        let status = response.status();
    
        // 1. 读取原始字节（会 consume response）
        let bytes = response.bytes().await.map_err(crate::error::RswappalyzerError::HttpError)?;
    
        log::debug!(
            "[WappalyzerGo] response size={} bytes, status={}",
            bytes.len(),
            status
        );
    
        // 2. 解析为原始规则库
        let original_lib = serde_json::from_slice(&bytes).map_err(|e| {
            let preview = String::from_utf8_lossy(&bytes[..bytes.len().min(200)]);
            log::warn!(
                "[WappalyzerGo] 响应体 JSON 解码失败：{}，前 200 字节预览：{}",
                e,
                preview
            );
            RswappalyzerError::RuleParseError(format!("响应体解码失败：{}", e))
        })?;
    
        Ok(original_lib)
    }
}

impl WappalyzerGoParser {
    /// 兼容原有逻辑：从 JSON Value 解析原始规则库（仅保留原始解析功能）
    pub fn parse_original_from_value(&self, value: &Value) -> RswResult<WappalyzerOriginalRuleLibrary> {
        Ok(serde_json::from_value(value.clone())?)
    }
}