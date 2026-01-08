//! 全局检测器单例管理
//! 核心职责：
//! 1. 维护进程生命周期内唯一的TechDetector实例
//! 2. 提供异步/同步初始化接口
//! 3. 支持懒加载初始化和手动注入规则库
//! 4. 统一错误处理和状态管理

use std::sync::Arc;
use once_cell::sync::{Lazy, OnceCell};
use rswappalyzer_engine::RuleLibrary;

use super::detector::TechDetector;
use crate::RuleConfig;
use crate::error::{RswResult, RswappalyzerError};

/// 全局检测器实例 - 线程安全单例
/// 设计说明：
/// - Lazy：延迟初始化，首次使用时创建
/// - Arc：多线程共享所有权
/// - OnceCell：确保实例仅初始化一次，进程内唯一
static GLOBAL_DETECTOR: Lazy<Arc<OnceCell<TechDetector>>> = Lazy::new(|| Arc::new(OnceCell::new()));

/// 初始化全局检测器（使用默认配置）
/// 特性：
/// 1. 幂等设计：已初始化则直接返回Ok(())
/// 2. 线程安全：基于OnceCell保证仅初始化一次
/// 3. 异步初始化：适配TechDetector::new的异步特性
/// 参数：config - 规则配置
/// 返回：初始化结果 | 错误（仅当并发初始化冲突时返回）
pub async fn init_global_detector(config: RuleConfig) -> RswResult<()> {
    // 幂等检查：已初始化则直接返回
    if GLOBAL_DETECTOR.get().is_some() {
        log::debug!("Global detector already initialized, skip reinitialization");
        return Ok(());
    }

    // 异步创建检测器实例
    let detector = TechDetector::new(config).await.map_err(|e| {
        RswappalyzerError::DetectorInitError(format!(
            "Failed to create TechDetector instance: {}",
            e
        ))
    })?;

    // 尝试设置全局实例（OnceCell保证仅一次成功）
    GLOBAL_DETECTOR.set(detector).map_err(|_| {
        RswappalyzerError::DetectorInitError(
            "Global detector initialization failed: instance already initialized by another thread".to_string()
        )
    })?;

    log::info!("Global TechDetector initialized successfully");
    Ok(())
}

/// 手动注入规则库，初始化全局检测器（同步接口）
/// 适用场景：预加载规则库后手动初始化
/// 参数：
/// - rule_lib: 预加载的规则库实例
/// - config: 规则配置
/// 返回：初始化结果 | 错误
pub fn init_global_detector_with_rules(rule_lib: RuleLibrary, config: RuleConfig) -> RswResult<()> {
    // 幂等检查：已初始化则直接返回
    if GLOBAL_DETECTOR.get().is_some() {
        log::debug!("Global detector already initialized, skip reinitialization with custom rules");
        return Ok(());
    }

    // 同步创建检测器实例（注入自定义规则库）
    let detector = TechDetector::with_rules(rule_lib, config).map_err(|e| {
        RswappalyzerError::DetectorInitError(format!(
            "Failed to create TechDetector with custom rules: {}",
            e
        ))
    })?;

    // 尝试设置全局实例
    GLOBAL_DETECTOR.set(detector).map_err(|_| {
        RswappalyzerError::DetectorInitError(
            "Global detector initialization failed: instance already initialized by another thread".to_string()
        )
    })?;

    log::info!("Global TechDetector initialized with custom rule library");
    Ok(())
}

/// 懒加载初始化全局检测器（内部辅助函数）
/// 特性：仅当实例未初始化时执行初始化
/// 参数：config - 规则配置（默认配置）
/// 返回：初始化结果 | 错误
async fn lazy_init(config: RuleConfig) -> RswResult<()> {
    if GLOBAL_DETECTOR.get().is_none() {
        log::debug!("Lazy initializing global TechDetector with default config");
        init_global_detector(config).await?;
    }
    Ok(())
}

/// 获取全局检测器实例（异步，自动懒加载）
/// 特性：
/// 1. 自动懒加载：未初始化则使用默认配置初始化
/// 2. 返回静态引用：进程生命周期内有效
/// 3. 精准错误：明确返回初始化失败原因
/// 返回：全局检测器静态引用 | 错误
pub(crate) async fn get_global_detector() -> RswResult<&'static TechDetector> {
    // 自动懒加载初始化（使用默认配置）
    lazy_init(Default::default()).await?;

    // 获取实例并返回精准错误
    GLOBAL_DETECTOR.get().ok_or_else(|| {
        RswappalyzerError::DetectorInitError(
            "Global detector initialization failed: instance not created".to_string()
        )
    })
}

/// 同步获取全局检测器实例（无自动初始化）
/// 注意：调用前需确保已手动初始化，否则返回错误
/// 返回：全局检测器静态引用 | 未初始化错误
#[allow(dead_code)]
pub(crate) fn get_global_detector_sync() -> RswResult<&'static TechDetector> {
    GLOBAL_DETECTOR.get().ok_or_else(|| {
        RswappalyzerError::DetectorNotInitialized(
            "Global TechDetector not initialized! Please call init_global_detector first".to_string()
        )
    })
}