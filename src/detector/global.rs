//! 全局检测器单例管理
use once_cell::sync::Lazy;
use std::sync::Arc;
use tokio::sync::OnceCell;

use super::detector::TechDetector;
use crate::error::{RswResult, RswappalyzerError};
use crate::config::{ConfigManager, GlobalConfig};

/// 全局检测器实例
static GLOBAL_DETECTOR: Lazy<Arc<OnceCell<TechDetector>>> = Lazy::new(|| {
    Arc::new(OnceCell::new())
});

/// 初始化全局检测器（默认配置）
pub async fn init_wappalyzer() -> RswResult<()> {
    init_wappalyzer_with_config(ConfigManager::get_default()).await
}

/// 带自定义配置初始化全局检测器
pub async fn init_wappalyzer_with_config(config: GlobalConfig) -> RswResult<()> {
    if GLOBAL_DETECTOR.get().is_some() {
        return Ok(());
    }

    let detector = TechDetector::new(config).await?;
    GLOBAL_DETECTOR.set(detector).map_err(|_| {
        RswappalyzerError::DetectorNotInitialized
    })?;

    Ok(())
}

/// 获取全局检测器
pub(crate) fn get_global_detector() -> RswResult<&'static TechDetector> {
    GLOBAL_DETECTOR.get()
        .ok_or(RswappalyzerError::DetectorNotInitialized)
}