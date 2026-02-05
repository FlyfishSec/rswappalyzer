//! TechDetector 核心实现
//!
//! 该模块提供技术检测的核心能力实现，包含所有构造逻辑与检测算法，
//! 设计原则：无全局依赖、无隐式状态、内存高效、线程安全。

use crate::error::{RswError, RswResult};
use crate::{RuleConfig, RuleLoader, RuleSource, RuleStage};
use http::HeaderMap;
use rswappalyzer_engine::automation::cache::AcAutomatonCache;
use rswappalyzer_engine::compiled::CompiledBundle;
use rswappalyzer_engine::{
    CoreError, RuleIndexer, RuleLibrary, RuleLibraryIndex, RuleLibraryRuntime,
};
use std::sync::Arc;

/// 技术检测器核心类型
///
/// 库的核心 API 入口，所有技术检测能力均通过该类型实例提供。
///
/// # 核心特性
/// - **内存高效**：核心依赖（规则库/AC 自动机缓存）通过 `Arc` 共享，`clone` 操作零成本
/// - **多源规则**：支持内置/本地文件/远程地址/预编译四种规则加载方式
/// - **线程安全**：基于 `Arc` 封装，可安全跨线程使用
/// - **无状态设计**：实例包含所有运行时依赖，无全局/隐式状态
///
/// # 使用约束
/// - 使用内置规则需启用 `embedded-rules` 特性
/// - 远程规则加载需异步运行时支持
///
/// # 示例
/// ```rust
/// use rswappalyzer::detector::TechDetector;
/// use rswappalyzer::RuleConfig;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // 创建默认配置的检测器
///     let config = RuleConfig::default();
///     let detector = TechDetector::new(config).await?;
///     
///     // 准备检测输入（HTTP 头、URL 列表、响应体）
///     let headers = http::HeaderMap::new();
///     let urls = &["https://example.com"];
///     let body = b"<html><head><title>Example</title></head></html>";
///     
///     // 执行检测
///     let result = detector.detect(&headers, urls, body)?;
///     println!("检测结果: {:?}", result);
///     
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone)]
pub struct TechDetector {
    /// 规则库运行时实例（包含编译后的规则包和 AC 自动机缓存）
    pub runtime_lib: Arc<RuleLibraryRuntime>,
    /// 检测器配置（包含规则来源、过滤策略等）
    pub config: RuleConfig,
    /// 规则库索引（仅非内置规则场景可用）
    pub rule_index: Option<Arc<RuleLibraryIndex>>,
}

impl TechDetector {
    /// 创建检测器实例（通用入口）
    ///
    /// 根据 `RuleConfig` 中指定的 `RuleOrigin` 自动选择规则加载策略：
    /// - `Embedded`: 使用内置预编译规则（需启用 `embedded-rules` 特性）
    /// - `LocalFile/RemoteOfficial/RemoteCustom`: 加载并编译指定规则
    ///
    /// # 参数
    /// - `config`: 检测器配置，包含规则来源、过滤策略等核心参数
    ///
    /// # 返回值
    /// 成功返回检测器实例，失败返回 `RswError`（包含规则加载/编译错误信息）
    pub async fn new(config: RuleConfig) -> RswResult<Self> {
        let (source, stage) = (&config.origin.source, &config.origin.stage);
        let (runtime_lib, rule_index): (Arc<RuleLibraryRuntime>, Option<Arc<RuleLibraryIndex>>);

        match (source, stage) {
            //RuleOrigin::Embedded => Self::with_embedded_rules(config),
            (RuleSource::Embedded, _) => {
                #[cfg(feature = "embedded-rules")]
                {
                    (runtime_lib, rule_index) = Self::with_embedded_rules_inner()?;
                }
                #[cfg(not(feature = "embedded-rules"))]
                {
                    return Err(RswError::FeatureError(
                        "embedded-rules feature required".into(),
                    ));
                }
            }

            (RuleSource::LocalFile(path), RuleStage::Compiled) => {
                let rule_loader = RuleLoader::new();
                let compiled_bundle = rule_loader.load_compiled_bundle(&path).await?;
                let ac_cache = AcAutomatonCache::new(&compiled_bundle)
                    .map_err(|e| RswError::CoreError(CoreError::from(e)))?;

                runtime_lib = Arc::new(RuleLibraryRuntime {
                    compiled_bundle: Arc::new(compiled_bundle),
                    ac_cache: Arc::new(ac_cache),
                });
                rule_index = None;
            }

            // 远程Compiled：不支持的配置
            (RuleSource::RemoteOfficial | RuleSource::RemoteCustom(_), RuleStage::Compiled) => {
                return Err(RswError::RuleConfigError(
                    "Remote rules do not support Compiled stage".into(),
                ));
            }

            // 本地已编译规则：直接加载编译包，规则索引返回None
            (
                RuleSource::LocalFile(_) | RuleSource::RemoteOfficial | RuleSource::RemoteCustom(_),
                RuleStage::Raw,
            ) => {
                let rule_loader = RuleLoader::new();
                let rule_lib = rule_loader.load(&config).await?;
                let rule_index_inner = RuleLibraryIndex::from_rule_library(&rule_lib)?;
                let compiled_bundle = RuleIndexer::build_compiled_library(&rule_index_inner, None)?;
                let ac_cache = AcAutomatonCache::new(&compiled_bundle)
                    .map_err(|e| RswError::CoreError(CoreError::from(e)))?;

                runtime_lib = Arc::new(RuleLibraryRuntime {
                    compiled_bundle: Arc::new(compiled_bundle),
                    ac_cache: Arc::new(ac_cache),
                });
                rule_index = Some(Arc::new(rule_index_inner));
            }
        }

        Ok(Self {
            runtime_lib,
            config,
            rule_index,
        })
    }

    /// 基于内存中已加载的规则库创建检测器
    ///
    /// 适用于预加载规则库后手动构建实例的场景，避免重复加载/编译规则，提升性能。
    ///
    /// # 参数
    /// - `rule_lib`: 内存中的规则库实例
    /// - `config`: 检测器配置
    ///
    /// # 返回值
    /// 成功返回检测器实例，失败返回 `RswError`
    pub fn with_rules(rule_lib: RuleLibrary, config: RuleConfig) -> RswResult<Self> {
        let rule_index = RuleLibraryIndex::from_rule_library(&rule_lib)?;
        let compiled_bundle = RuleIndexer::build_compiled_library(&rule_index, None)?;
        let ac_cache = AcAutomatonCache::new(&compiled_bundle)
            .map_err(|e| RswError::CoreError(CoreError::from(e)))?;

        let runtime_lib = RuleLibraryRuntime {
            compiled_bundle: Arc::new(compiled_bundle),
            ac_cache: Arc::new(ac_cache),
        };

        Ok(Self {
            runtime_lib: Arc::new(runtime_lib),
            config,
            rule_index: Some(Arc::new(rule_index)),
        })
    }

    /// 使用内置预编译规则创建检测器
    ///
    /// 需启用 `embedded-rules` 特性，适用于无需外部规则文件的场景。
    ///
    /// # 参数
    /// - `config`: 检测器配置
    ///
    /// # 返回值
    /// 成功返回检测器实例，失败返回 `RswError`
    #[cfg(feature = "embedded-rules")]
    pub fn with_embedded_rules(config: RuleConfig) -> RswResult<Self> {
        let (runtime_lib, rule_index) = Self::with_embedded_rules_inner()?;
        Ok(Self {
            runtime_lib,
            config,
            rule_index,
        })
    }

    fn with_embedded_rules_inner(
    ) -> RswResult<(Arc<RuleLibraryRuntime>, Option<Arc<RuleLibraryIndex>>)> {
        let compiled_bundle = crate::rswappalyzer_rules::EMBEDDED_COMPILED_BUNDLE.clone();
        let ac_cache = AcAutomatonCache::new(&compiled_bundle)
            .map_err(|e| RswError::CoreError(CoreError::from(e)))?;

        let runtime_lib = Arc::new(RuleLibraryRuntime {
            compiled_bundle,
            ac_cache: Arc::new(ac_cache),
        });
        // 内置规则无索引，返回 None
        Ok((runtime_lib, None))
    }

    /// 基于预编译规则包创建检测器
    ///
    /// 性能最优的创建方式，适用于离线编译规则后直接复用的场景。
    ///
    /// # 参数
    /// - `compiled_bundle`: 预编译的规则包
    /// - `rule_index`: 规则库索引
    /// - `config`: 检测器配置
    ///
    /// # 返回值
    /// 成功返回检测器实例，失败返回 `RswError`
    pub fn with_compiled_lib(
        compiled_bundle: CompiledBundle,
        rule_index: RuleLibraryIndex,
        config: RuleConfig,
    ) -> RswResult<Self> {
        let ac_cache = AcAutomatonCache::new(&compiled_bundle)
            .map_err(|e| RswError::CoreError(CoreError::from(e)))?;

        let runtime_lib = RuleLibraryRuntime {
            compiled_bundle: Arc::new(compiled_bundle),
            ac_cache: Arc::new(ac_cache),
        };

        Ok(Self {
            runtime_lib: Arc::new(runtime_lib),
            config,
            rule_index: Some(Arc::new(rule_index)),
        })
    }

    /// 执行技术检测（核心检测方法）
    ///
    /// 基于 HTTP 头、URL 列表和响应体执行技术栈检测，无全局依赖，所有状态均来自实例。
    /// 该方法标记为 `#[inline(always)]` 以优化调用性能。
    ///
    /// # 参数
    /// - `headers`: HTTP 响应头
    /// - `urls`: 相关 URL 列表
    /// - `body`: HTTP 响应体字节流
    ///
    /// # 返回值
    /// 成功返回检测结果 `DetectResult`，失败返回 `RswError`
    #[inline(always)]
    pub fn detect(
        &self,
        headers: &HeaderMap,
        urls: &[&str],
        body: &[u8],
    ) -> RswResult<super::DetectResult> {
        super::detection::core::detect(self, headers, urls, body)
    }

    /// 执行检测并输出耗时日志（仅调试模式）
    ///
    /// 与 `detect` 功能一致，但会输出检测过程的耗时日志，仅在 `debug_assertions` 启用时可用。
    ///
    /// # 参数
    /// - `headers`: HTTP 响应头
    /// - `urls`: 相关 URL 列表
    /// - `body`: HTTP 响应体字节流
    ///
    /// # 返回值
    /// 成功返回检测结果 `DetectResult`，失败返回 `RswError`
    #[cfg(debug_assertions)]
    #[inline(always)]
    pub fn detect_with_log(
        &self,
        headers: &HeaderMap,
        urls: &[&str],
        body: &[u8],
    ) -> RswResult<super::DetectResult> {
        super::detection::detect_with_log(self, headers, urls, body)
    }

    // ========== 只读属性访问器 ==========
    /// 获取检测器配置（只读）
    ///
    /// 符合 Rust 封装原则，提供配置的只读访问，避免外部修改实例状态。
    ///
    /// # 返回值
    /// 检测器配置的不可变引用
    pub fn config(&self) -> &RuleConfig {
        &self.config
    }

    /// 获取规则库索引（可选）
    ///
    /// 仅在非内置规则场景下可用，主要用于调试或扩展功能开发。
    ///
    /// # 返回值
    /// 规则库索引的可选不可变引用
    pub fn rule_index(&self) -> Option<&RuleLibraryIndex> {
        self.rule_index.as_deref()
    }
}
