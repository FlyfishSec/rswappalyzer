//! 检测模块：技术检测核心逻辑
pub mod global;
pub mod analyzer;
pub mod detector;

// 导出核心接口
pub use self::global::{init_wappalyzer, init_wappalyzer_with_config};
pub use self::detector::{
    TechDetector,
    header_map_to_hashmap,
    detect_technologies_wappalyzer,
    detect_technologies_wappalyzer_hashmap,
    detect_technologies_wappalyzer_lite,
    detect_technologies_wappalyzer_lite_hashmap,
    detect_technologies_wappalyzer_with_cookies,
    detect_technologies_wappalyzer_lite_with_cookies,
};