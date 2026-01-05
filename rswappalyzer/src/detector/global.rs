//! 全局检测器单例管理
use std::sync::Arc;
//use tokio::sync::OnceCell;
use once_cell::sync::{Lazy, OnceCell};

use super::detector::TechDetector;
use crate::RuleConfig;
use crate::error::{RswResult, RswappalyzerError};
use crate::rule::core::RuleLibrary;

/// 全局检测器实例 - 异步安全单例，进程生命周期内唯一
static GLOBAL_DETECTOR: Lazy<Arc<OnceCell<TechDetector>>> = Lazy::new(|| {
    Arc::new(OnceCell::new())
});


/// 初始化全局检测器（使用默认配置）
pub async fn init_global_detector(config: RuleConfig) -> RswResult<()> {
    if GLOBAL_DETECTOR.get().is_some() {
        return Ok(());
    }

    let detector = TechDetector::new(config).await?;

    GLOBAL_DETECTOR.set(detector).map_err(|_| {
        RswappalyzerError::DetectorInitError(
            "全局检测器初始化失败：实例已被其他线程初始化".to_string()
        )
    })?;

    Ok(())
}

/// 手动注入规则库，初始化全局检测器
pub fn init_global_detector_with_rules(rule_lib: RuleLibrary, config: RuleConfig) -> RswResult<()> {
    if GLOBAL_DETECTOR.get().is_some() {
        return Ok(());
    }

    let detector = TechDetector::with_rules(rule_lib, config)?;
    GLOBAL_DETECTOR.set(detector).map_err(|_| {
        RswappalyzerError::DetectorInitError("全局检测器初始化失败：实例已被其他线程初始化".to_string())
    })?;

    Ok(())
}


// 懒加载初始化
async fn lazy_init(config: RuleConfig) -> RswResult<()> {
    if GLOBAL_DETECTOR.get().is_none() {
        init_global_detector(config).await?;
    }
    Ok(())
}

/// 获取全局检测器实例
pub(crate) async fn get_global_detector() -> RswResult<&'static TechDetector> {
    // 自动懒加载初始化
    lazy_init(Default::default()).await?;

    // 获取实例，返回精准错误
    GLOBAL_DETECTOR.get().ok_or_else(|| {
        RswappalyzerError::DetectorInitError("全局检测器初始化失败：实例未创建".to_string())
    })
}


/// 同步获取全局检测器
#[allow(dead_code)]
pub(crate) fn get_global_detector_sync() -> RswResult<&'static TechDetector> {
    GLOBAL_DETECTOR.get().ok_or_else(|| {
        RswappalyzerError::DetectorNotInitialized(
            "全局检测器未初始化!".to_string()
        )
    })
}