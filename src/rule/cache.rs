//! 规则缓存管理
//! 仅处理规则库的本地序列化（MessagePack）和反序列化

use rmp_serde::{Serializer, from_slice};
use serde::Serialize;
use tracing::debug;

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
        let rule_lib: RuleLibrary = from_slice(&cache_data)
            .map_err(|e| RswappalyzerError::MsgPackError(format!("反序列化失败：{}", e)))?;

        debug!("缓存文件反序列化成功，技术规则数：{}，分类规则数：{}", rule_lib.tech_rules.len(), rule_lib.category_rules.len());

        Ok(rule_lib)
    }

    /// 将规则库缓存到本地
    pub async fn save_to_cache(config: &GlobalConfig, rule_lib: &RuleLibrary) -> RswResult<()> {
        let cache_path = &config.rule_cache_path;
        let mut cache_data = Vec::new();

        // MessagePack序列化
        rule_lib.serialize(&mut Serializer::new(&mut cache_data))
            .map_err(|e| RswappalyzerError::MsgPackError(format!("序列化失败：{}", e)))?;

        debug!("规则库序列化成功，序列化后数据大小：{} 字节", cache_data.len());

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