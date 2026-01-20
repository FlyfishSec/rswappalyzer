//! Tech detector core module
//! 技术检测器核心
//! 核心职责：
//! 1. 规则库加载与编译（内置/本地/远程规则）
//! 2. 多维度技术检测（URL/Header/Cookie/HTML/Script/Meta）
//! 3. 检测结果聚合与关联推导
//! 4. 提供基础检测/带耗时统计/HashMap输入等多版本接口

// 导出核心结构体和方法
pub use self::constructor::TechDetector;
pub use self::global_api::detect;
#[cfg(debug_assertions)]
pub use self::global_api::detect_log;

// 子模块
mod constructor;
mod global_api;

// 检测逻辑模块
pub mod detection;
// 输入适配模块
pub mod adapters;

pub mod global;
//pub mod evidence_builder;

// 导出核心接口
pub use self::global::{init_global_detector, init_global_detector_with_rules};
pub use crate::result::detect_result::Technology;
pub use crate::{DetectResult, RuleConfig, RuleOrigin};

// pub use self::global_api::{
//     TechDetector,
//     detect,
// };
