//! 检测模块：技术检测核心逻辑
pub mod global;
pub mod detector;

// 导出核心接口
pub use self::global::{init_global_detector, init_global_detector_with_rules};
pub use self::detector::{
    TechDetector,
    detect,
};
