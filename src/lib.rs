//! rswappalyzer - Rust Wappalyzer网站技术栈检测工具

// 导出全局错误类型
pub use self::error::{RswappalyzerError, RswResult};

// 导出配置模块
pub use self::config::{GlobalConfig, ConfigManager, CustomConfigBuilder};

// 导出规则模块核心接口
pub use self::rule::{
    Technology, TechnologyLite, TechRule, CategoryRule, RuleLibrary,
    RuleLoader, RuleCacheManager
};

// 导出提取模块核心接口
pub use self::extractor::HtmlExtractor;

// 导出工具模块核心接口
pub use self::utils::{
    VersionExtractor, HeaderConverter, DetectionUpdater
};

// 导出编译模块核心接口
pub use self::compiler::{
    CompiledTechRule, CompiledRuleLibrary, RuleCompiler, CompiledPattern
};

// 导出检测模块核心接口（含兼容原有调用的简化接口）
pub use self::detector::{
    TechDetector,
    init_wappalyzer,
    init_wappalyzer_with_config,
    header_map_to_hashmap,
    detect_technologies_wappalyzer,
    detect_technologies_wappalyzer_hashmap,
    detect_technologies_wappalyzer_lite,
    detect_technologies_wappalyzer_lite_hashmap,
    detect_technologies_wappalyzer_with_cookies,
    detect_technologies_wappalyzer_lite_with_cookies,
};

// 声明所有子模块
pub mod config;
pub mod error;
pub mod rule;
pub mod extractor;
pub mod utils;
pub mod compiler;
pub mod detector;
