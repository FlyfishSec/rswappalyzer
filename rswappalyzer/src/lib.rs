//! rswappalyzer - Rust Wappalyzer 高性能Web指纹识别库

pub mod config;
pub mod detector;
pub mod analyzer;
pub mod error;
pub mod rule;
pub mod utils;


// 导出全局错误类型
pub use self::error::{RswResult, RswappalyzerError};

// 导出配置模块核心结构体与构建器
pub use crate::config::rule::{
    CustomConfigBuilder, RetryPolicy, RuleConfig, RuleOptions, RuleOrigin,
};

// 导出规则模块核心接口与数据结构
pub use crate::rule::{RuleCacheManager, RuleLoader, DetectResult};
pub use crate::rule::indexer::index_pattern::CompiledRuleLibrary;
pub use crate::rule::indexer::rule_indexer::RuleLibraryIndex;

// 导出HTML提取工具核心接口
pub use crate::utils::extractor::HtmlExtractor;

// 导出通用工具模块核心能力
pub use crate::utils::{DetectionUpdater, HeaderConverter, VersionExtractor};

// 导出检测模块核心接口（包含兼容历史调用的简化封装接口）
pub use crate::detector::{
    TechDetector, init_global_detector, init_global_detector_with_rules,
};

// 导出规则相关核心结构体与解析器
pub use rule::cleaner::RuleCleaner;
pub use rule::core::{CategoryRule, MatchCondition, RuleLibrary, TechMatcher};
pub use rule::source::{FingerprintHubParser, RuleSourceParser, WappalyzerGoParser};

// 嵌入式固化规则库 - 仅在开启embedded-rules特性时编译
#[cfg(feature = "embedded-rules")]
#[allow(clippy::all)]
#[allow(dead_code)]
#[allow(rust_analyzer::unresolved_env)] // 忽略OUT_DIR未解析提示
pub mod rswappalyzer_rules {
    use super::*;
    use lz4_flex::decompress_size_prepended;
    use once_cell::sync::Lazy;
    use std::sync::Arc;

    /// LZ4解压缩封装 - 适配build.rs的压缩规则，统一错误处理与日志提示
    fn lz4_decompress(bytes: &[u8]) -> Result<Vec<u8>, RswappalyzerError> {
        decompress_size_prepended(bytes)
            .map_err(|e| RswappalyzerError::RuleLoadError(format!("LZ4解压缩规则库失败: {:?}, 压缩包字节长度: {}", e, bytes.len())))
    }

    // 文件名由build_config.json配置，build.rs注入环境变量，全程联动
    #[allow(dead_code)]
    static COMPILED_LIB_COMPRESSED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/", env!("COMPILED_LIB_FILENAME")));

    /// 全局懒加载的编译后规则库单例 - 运行期首次访问初始化，内存中仅一份实例，线程安全
    pub static EMBEDDED_COMPILED_LIB: Lazy<Arc<CompiledRuleLibrary>> = Lazy::new(|| {
        let decompressed = lz4_decompress(COMPILED_LIB_COMPRESSED).unwrap_or_else(|e| {
            eprintln!("致命错误: 嵌入式规则库LZ4解压缩失败 - {}", e);
            panic!("规则库解压缩异常，请检查build.rs的enable_compress配置项");
        });

        // JSON反序列化
        let lib = serde_json::from_slice(&decompressed).unwrap_or_else(|e| {
            eprintln!("致命错误: 嵌入式规则库反序列化失败 - {:?}", e);
            eprintln!("调试信息: 解压缩后规则库字节长度: {}", decompressed.len());
            panic!("规则库序列化异常，请确认build.rs使用JSON序列化规则库");
        });

        Arc::new(lib)
    });
}