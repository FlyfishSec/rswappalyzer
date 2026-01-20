//! ```text
//!                                           _                    
//!  _ __ _____      ____ _ _ __  _ __   __ _| |_   _ _______ _ __
//! | '__/ __\ \ /\ / / _` | '_ \| '_ \ / _` | | | | |_  / _ \ '__|
//! | |  \__ \\ V  V / (_| | |_) | |_) | (_| | | |_| |/ /  __/ |
//! |_|  |___/ \_/\_/ \__,_| .__/| .__/ \__,_|_|\__, /___\___|_|
//!                        |_|   |_|            |___/
//! ```
//! rswappalyzer - High-performance Wappalyzer-compatible rule detection engine.
//!
//! Core Features:
//! 1. Multi-dimensional Web technology detection
//!    (URL / Header / Cookie / HTML / Script / Meta)
//! 2. Supports built-in, local, and remote rule sources
//! 3. Extreme performance with an AC automaton–based pruning engine,
//!    enabling millisecond-level detection for 7,000+ rules
//!
//! ![Crates.io](https://img.shields.io/crates/v/rswappalyzer)
//! ![License](https://img.shields.io/crates/l/rswappalyzer)
//! ![MSRV](https://img.shields.io/badge/MSRV-1.75+-blue)

// 模块导出
pub mod analyzer; // 多维度分析器模块（URL/Header/Cookie/HTML等）
pub mod config; // 配置模块（规则配置/重试策略/加载源）
pub mod detector; // 检测器核心模块（全局单例/检测接口）
pub mod error; // 错误处理模块（统一错误类型/结果类型）
pub mod result; // 检测结果核心模块
pub mod rule; // 规则模块（加载/缓存/检测结果）
pub mod utils; // 通用工具模块（Header转换/版本提取/检测更新）

// 全局错误类型
pub use self::error::{RswResult, RswappalyzerError};

// 配置模块核心结构体与构建器
pub use crate::config::rule::{
    CustomConfigBuilder, RetryPolicy, RuleConfig, RuleOptions, RuleOrigin,
};

// 规则模块核心接口与数据结构
pub use crate::result::detect_result::{DetectResult, Technology};
pub use crate::rule::{RuleCacheManager, RuleLoader};

// HTML提取工具核心接口
pub use crate::utils::extractor::HtmlExtractor;

// 通用工具模块核心能力
pub use crate::utils::{DetectionUpdater, HeaderConverter, VersionExtractor, timing::time_it};

// 检测模块核心接口
pub use crate::detector::{init_global_detector, init_global_detector_with_rules, TechDetector};

// ========== 嵌入式固化规则库（仅embedded-rules特性开启时编译） ==========
/// 嵌入式规则库模块（仅启用embedded-rules特性时编译）
/// 特性：
/// 1. 编译期压缩：规则库通过build.rs压缩为LZ4格式嵌入二进制
/// 2. 运行期懒加载：首次访问时解压缩并反序列化，全程线程安全
/// 3. 单例管理：Arc封装，内存中仅一份实例，多线程共享
#[cfg(feature = "embedded-rules")]
#[allow(clippy::all)]
#[allow(dead_code)]
#[allow(rust_analyzer::unresolved_env)] // 忽略OUT_DIR未解析提示
pub mod rswappalyzer_rules {
    use super::*;
    use log::error;
    use lz4_flex::decompress_size_prepended;
    use once_cell::sync::Lazy;
    use rswappalyzer_engine::{compiled::CompiledBundle};
    use std::sync::Arc;

    /// LZ4解压缩封装函数
    /// 功能：
    /// 1. 适配build.rs的压缩规则（size-prepended格式）
    /// 2. 统一错误处理，补充上下文信息
    /// 3. 日志友好的错误提示
    /// 参数：bytes - 压缩后的LZ4字节数组
    /// 返回：解压缩后的字节数组 | 错误（含详细上下文）
    fn lz4_decompress(bytes: &[u8]) -> Result<Vec<u8>, RswappalyzerError> {
        decompress_size_prepended(bytes).map_err(|e| {
            RswappalyzerError::RuleLoadError(format!(
                "Failed to decompress rule library with LZ4: {:?}, compressed size: {} bytes",
                e,
                bytes.len()
            ))
        })
    }

    /// 编译期嵌入的压缩规则库
    /// 说明：
    /// - 文件名由build_config.json配置
    /// - build.rs注入COMPILED_BUNDLE_FILENAME环境变量
    /// - OUT_DIR为编译输出目录，由Rust编译器自动设置
    #[allow(dead_code)]
    static COMPILED_BUNDLE_COMPRESSED: &[u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/", env!("COMPILED_BUNDLE_FILENAME")));

    /// 全局懒加载的编译后规则库单例
    /// 设计：
    /// 1. Lazy：首次访问时初始化，避免启动耗时
    /// 2. Arc：多线程共享，无拷贝开销
    /// 3. 严格错误处理：初始化失败时panic，确保核心功能可用
    pub static EMBEDDED_COMPILED_BUNDLE: Lazy<Arc<CompiledBundle>> = Lazy::new(|| {
        // 步骤1：LZ4解压缩
        let decompressed = lz4_decompress(COMPILED_BUNDLE_COMPRESSED).unwrap_or_else(|e| {
            error!(
                "Failed to decompress embedded rule library: error = {:?}, compressed_size = {}",
                e,
                COMPILED_BUNDLE_COMPRESSED.len()
            );
            panic!(
                "Embedded rule library decompression failed. \
         This indicates a build-time error. Please rebuild the project."
            );
        });

        // 步骤2：JSON反序列化为CompiledRuleLibrary
        let lib: CompiledBundle = serde_json::from_slice(&decompressed).unwrap_or_else(|e| {
            eprintln!(
                "Fatal error: Failed to deserialize embedded rule library - {:?}",
                e
            );
            eprintln!(
                "Debug info: Decompressed rule library size: {} bytes",
                decompressed.len()
            );
            panic!(
                "Failed to load embedded rule library. \
     The embedded rules appear to be corrupted or incompatible. \
     Please clean the build directory and rebuild the project."
            );
        });

        // 步骤3：封装为Arc单例
        Arc::new(lib)
    });
}
