//! 全局检测器单例管理
//!
//! 核心职责：
//! 1. 维护进程生命周期内唯一的 TechDetector 实例
//! 2. 提供异步 / 同步初始化接口
//! 3. 支持自动懒加载初始化
//! 4. 统一错误处理和状态管理

use once_cell::sync::OnceCell;
use rswappalyzer_engine::RuleLibrary;

use crate::{RuleConfig, TechDetector};
use crate::error::{RswResult, RswappalyzerError};

/// 全局检测器实例（线程安全单例）
///
/// OnceCell guarantees:
/// - 仅初始化一次
/// - 线程安全
/// - &'static 生命周期访问
static GLOBAL_DETECTOR: OnceCell<TechDetector> = OnceCell::new();

/// 异步初始化全局检测器（默认规则加载）
///
/// 特性：
/// 1. 幂等：已初始化直接返回 Ok(())
/// 2. 并发安全：多线程同时调用仅一次成功
pub async fn init_global_detector(config: RuleConfig) -> RswResult<()> {
    if GLOBAL_DETECTOR.get().is_some() {
        log::debug!("Rswappalyzer detector already initialized, skip");
        return Ok(());
    }

    let detector = TechDetector::new(config).await.map_err(|e| {
        RswappalyzerError::DetectorInitError(format!(
            "Failed to create Rswappalyzer detector: {}",
            e
        ))
    })?;

    GLOBAL_DETECTOR.set(detector).map_err(|_| {
        RswappalyzerError::DetectorInitError(
            "Rswappalyzer detector already initialized by another thread".to_string(),
        )
    })?;

    log::info!("Rswappalyzer detector initialized");
    Ok(())
}

/// 同步初始化全局检测器（注入自定义规则库）
pub fn init_global_detector_with_rules(
    rule_lib: RuleLibrary,
    config: RuleConfig,
) -> RswResult<()> {
    if GLOBAL_DETECTOR.get().is_some() {
        log::debug!("Rswappalyzer detector already initialized, skip");
        return Ok(());
    }

    let detector = TechDetector::with_rules(rule_lib, config).map_err(|e| {
        RswappalyzerError::DetectorInitError(format!(
            "Failed to create Rswappalyzer detector with custom rules: {}",
            e
        ))
    })?;

    GLOBAL_DETECTOR.set(detector).map_err(|_| {
        RswappalyzerError::DetectorInitError(
            "Rswappalyzer detector already initialized by another thread".to_string(),
        )
    })?;

    log::info!("Rswappalyzer detector initialized with custom rule library");
    Ok(())
}

/// 自动懒加载初始化（内部使用）
async fn lazy_init_default() -> RswResult<()> {
    if GLOBAL_DETECTOR.get().is_none() {
        log::debug!("Lazy initializing Rswappalyzer detector");
        init_global_detector(Default::default()).await?;
    }
    Ok(())
}

/// 获取全局检测器（异步，自动懒加载）
pub(crate) async fn get_global_detector() -> RswResult<&'static TechDetector> {
    lazy_init_default().await?;

    GLOBAL_DETECTOR.get().ok_or_else(|| {
        RswappalyzerError::DetectorInitError(
            "Rswappalyzer detector initialization failed".to_string(),
        )
    })
}

/// 获取全局检测器（同步，不自动初始化）
#[allow(dead_code)]
pub(crate) fn get_global_detector_sync() -> RswResult<&'static TechDetector> {
    GLOBAL_DETECTOR.get().ok_or_else(|| {
        RswappalyzerError::DetectorNotInitialized(
            "Rswappalyzer detector not initialized, call init_global_detector first".to_string(),
        )
    })
}
