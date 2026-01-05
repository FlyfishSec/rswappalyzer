//! FingerprintHub 规则解析器
use async_trait::async_trait;
use crate::{RuleSourceParser, error::{RswResult}, rule::{RuleFileType, source::fingerprinthub::original::FingerprintHubOriginalRuleList}};


/// FingerprintHub 规则解析器
#[derive(Debug, Clone, Default)]
pub struct FingerprintHubParser;

#[async_trait]
impl RuleSourceParser<FingerprintHubOriginalRuleList> for FingerprintHubParser {
    fn rule_file_type(&self) -> RuleFileType {
        RuleFileType::FingerprintHubJson
    }

    /// 从字节流解析 FingerprintHub 原始规则列表
    fn parse_original_from_bytes(&self, bytes: &[u8]) -> RswResult<FingerprintHubOriginalRuleList> {
        Ok(serde_json::from_slice(bytes)?)
    }

    /// 从 HTTP 响应解析 FingerprintHub 原始规则列表
    #[cfg(feature = "remote-loader")]
    async fn parse_original_from_response(&self, response: reqwest::Response) -> RswResult<FingerprintHubOriginalRuleList> {
        // 1. 先读取原始字节，避免 reqwest 自动解码导致的问题
        let bytes = response.bytes().await.map_err(crate::error::RswappalyzerError::HttpError)?;

        log::debug!(
            "[FingerprintHub] response size={} bytes",
            bytes.len()
        );

        // 2. 尝试解析 JSON 为原始规则列表，失败时打印前 200 字节辅助排查
        let original_list = serde_json::from_slice(&bytes).map_err(|e| {
            let preview = String::from_utf8_lossy(&bytes[..bytes.len().min(200)]);
            warn!(
                "[FingerprintHub] JSON 解析失败，前 200 字节: {}",
                preview
            );
            RswappalyzerError::RuleParseError(format!("JSON解析失败：{}", e))
        })?;

        Ok(original_list)
    }

    /// 从字符串解析 FingerprintHub 原始规则列表（默认实现补充，可选）
    fn parse_original_from_str(&self, content: &str) -> RswResult<FingerprintHubOriginalRuleList> {
        Ok(serde_json::from_str(content)?)
    }
}

impl FingerprintHubParser {
    /// 兼容原有逻辑：解析原始规则列表（仅保留原始解析功能）
    pub fn parse_original_rules(&self, bytes: &[u8]) -> RswResult<FingerprintHubOriginalRuleList> {
        self.parse_original_from_bytes(bytes)
    }
}