//! 规则缓存管理
//! 仅处理规则库的本地序列化（MessagePack）和反序列化

use rmp_serde::{Serializer, from_slice};
use serde::Serialize;

use super::model::RuleLibrary;
use crate::error::{RswResult, RswappalyzerError};
use crate::config::GlobalConfig;

/// 规则缓存管理器
pub struct RuleCacheManager;

impl RuleCacheManager {
    /// 从本地缓存加载规则库
    pub async fn load_from_cache(config: &GlobalConfig) -> RswResult<RuleLibrary> {
        let cache_path = &config.rule_cache_path;
        let cache_data = tokio::fs::read(cache_path).await?;

        // MessagePack反序列化
        let rule_lib = from_slice(&cache_data)
            .map_err(|e| RswappalyzerError::MsgPackError(format!("反序列化失败：{}", e)))?;

        Ok(rule_lib)
    }

    /// 将规则库缓存到本地
    pub async fn save_to_cache(config: &GlobalConfig, rule_lib: &RuleLibrary) -> RswResult<()> {
        let cache_path = &config.rule_cache_path;
        let mut cache_data = Vec::new();

        // MessagePack序列化
        rule_lib.serialize(&mut Serializer::new(&mut cache_data))
            .map_err(|e| RswappalyzerError::MsgPackError(format!("序列化失败：{}", e)))?;

        // 写入文件
        tokio::fs::write(cache_path, cache_data).await?;
        Ok(())
    }

    /// 清除本地缓存
    pub async fn clear_cache(config: &GlobalConfig) -> RswResult<()> {
        let cache_path = &config.rule_cache_path;
        if cache_path.exists() {
            tokio::fs::remove_file(cache_path).await?;
        }
        Ok(())
    }
}