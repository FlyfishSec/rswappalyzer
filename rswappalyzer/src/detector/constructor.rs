//! # 技术检测器核心模块 (detector)
//! 
//! 提供技术栈检测的核心载体 `TechDetector` 结构体，封装规则库、运行时缓存、配置等核心依赖，
//! 支持多种规则库加载方式（内置规则、内存规则、预编译规则、运行时加载规则），是整个检测能力的入口载体。
//! 
//! ## 核心设计原则
//! 1. 内存高效：核心依赖（编译规则库、AC自动机缓存）使用 `Arc` 共享，避免数据拷贝；
//! 2. 多源规则支持：兼容内置、本地文件、远程、预编译等多种规则来源；
//! 3. 特性化设计：内置规则通过 `embedded-rules` 特性控制，按需编译；
//! 4. 零成本抽象：方法标记为内联优化，Arc 克隆仅拷贝指针，无数据拷贝开销。
//! 
//! ## 核心结构体
//! - `TechDetector`: 技术检测器核心结构体，承载所有检测依赖；
//! 
//! ## 核心创建方式
//! 1. `with_rules`: 使用内存中已加载的 `RuleLibrary` 创建检测器；
//! 2. `with_embedded_rules`: 使用内置预编译规则（需开启 `embedded-rules` 特性）；
//! 3. `with_compiled_lib`: 使用预编译的 `CompiledBundle` 创建检测器；
//! 4. `new`: 通用创建入口，根据 `RuleOrigin` 自动选择规则加载方式。

use crate::error::{RswResult};
use crate::{RuleConfig, RuleLoader, RuleOrigin};
use rswappalyzer_engine::automation::cache::AcAutomatonCache;
use rswappalyzer_engine::compiled::CompiledBundle;
use rswappalyzer_engine::{
    CoreError, RuleIndexer, RuleLibrary, RuleLibraryIndex, RuleLibraryRuntime,
};
use std::sync::Arc;

/// 技术检测器核心结构体
/// 
/// 检测能力的核心载体，封装规则库、运行时缓存、配置等所有检测依赖，
/// 所有检测方法（`detect`/`detect_with_log`）均基于该结构体实例调用。
/// 
/// # 设计说明
/// - 内存模型：核心依赖（`runtime_lib`）使用 `Arc` 共享，支持多线程安全共享，无数据拷贝；
/// - 字段可见性：`runtime_lib`/`config` 为 `pub(crate)`，仅对内暴露，保证封装性；
/// - 可选字段：`rule_index` 为可选，仅用于调试/扩展，不影响核心检测逻辑。
/// 
/// # 字段说明
/// - `runtime_lib`: 运行时规则库，包含编译后的规则包和AC自动机缓存（Arc共享）；
/// - `config`: 规则配置，保留规则加载/检测的上下文配置；
/// - `rule_index`: 规则库索引（可选），用于规则调试、扩展分析等场景。
#[derive(Debug, Clone)]
pub struct TechDetector {
    /// 运行时规则库（编译规则包 + AC自动机缓存），Arc共享保证多线程安全
    pub(crate) runtime_lib: Arc<RuleLibraryRuntime>,
    /// 规则配置上下文，保留规则加载/检测的核心配置
    #[allow(dead_code)]
    pub(crate) config: RuleConfig,
    /// 规则库索引（可选），用于规则调试、扩展分析，非核心依赖
    pub rule_index: Option<Arc<RuleLibraryIndex>>,
}

impl TechDetector {
    /// 使用内存中的RuleLibrary创建检测器
    /// 
    /// 适用场景：预加载规则库（如自定义解析规则文件）后，手动构建检测器实例。
    /// 核心流程：规则库索引构建 → 规则编译 → AC自动机缓存初始化 → 运行时库封装。
    /// 
    /// # 性能特性
    /// - 规则编译为一次性开销，AC自动机缓存初始化后通过Arc共享，多实例无重复构建成本；
    /// - 返回实例支持Clone（仅拷贝Arc指针，零成本）。
    /// 
    /// # 参数
    /// - `rule_lib`: 内存中的完整规则库实例（已加载未编译）；
    /// - `config`: 规则配置，控制检测行为、规则过滤等。
    /// 
    /// # 返回值
    /// 成功返回检测器实例，失败返回 `RswResult` 封装的错误（如规则编译失败、缓存初始化失败）。
    pub fn with_rules(rule_lib: RuleLibrary, config: RuleConfig) -> RswResult<Self> {
        // 构建规则库索引（为编译做准备）
        let rule_index = RuleLibraryIndex::from_rule_library(&rule_lib)?;
        // 编译规则库为运行时可执行的CompiledBundle
        let compiled_bundle = RuleIndexer::build_compiled_library(&rule_index, None)?;

        // 初始化AC自动机缓存（基于编译后的规则包）
        let ac_cache = AcAutomatonCache::new(&compiled_bundle).map_err(CoreError::from)?;

        // 构建运行时规则库（Arc封装，支持多实例共享）
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

    /// 使用内置规则创建检测器（仅embedded-rules特性开启时可用）
    /// 
    /// 适用场景：快速启动检测能力，无需手动加载/编译规则，依赖内置预编译规则库。
    /// 核心优势：零规则加载/编译开销，启动速度最快，适合生产环境快速集成。
    /// 
    /// # 特性约束
    /// - 仅当 `embedded-rules` 特性开启时可用，未开启时编译报错；
    /// - 内置规则为预编译版本，无法动态修改，适合规则稳定的场景。
    /// 
    /// # 性能特性
    /// - 零编译开销：直接复用预编译的 `CompiledBundle`（Arc克隆，零成本）；
    /// - AC缓存初始化仅一次，后续实例共享缓存。
    /// 
    /// # 参数
    /// - `config`: 规则配置，控制检测行为、规则过滤等。
    /// 
    /// # 返回值
    /// 成功返回检测器实例，失败返回 `RswResult` 封装的错误（如AC缓存初始化失败）。
    #[cfg(feature = "embedded-rules")]
    pub fn with_embedded_rules(config: RuleConfig) -> RswResult<Self> {
        // 直接获取内嵌规则库的 Arc 引用（预编译，零拷贝）
        let compiled_bundle = crate::rswappalyzer_rules::EMBEDDED_COMPILED_BUNDLE.clone();

        // 基于预编译规则包创建AC自动机缓存（无编译开销）
        let ac_cache = AcAutomatonCache::new(&compiled_bundle).map_err(CoreError::from)?;

        // 构建运行时规则库（仅移动 Arc 指针，无数据拷贝）
        let runtime_lib = RuleLibraryRuntime {
            compiled_bundle, // Arc 克隆后移动，零成本
            ac_cache: Arc::new(ac_cache),
        };

        Ok(Self {
            runtime_lib: Arc::new(runtime_lib),
            config,
            rule_index: None,
        })
    }

    /// 使用已编译的规则库创建检测器
    /// 
    /// 适用场景：自定义编译规则库（如离线编译、自定义规则优化）后，直接复用编译结果，
    /// 避免重复编译开销，适合规则频繁复用的场景。
    /// 
    /// # 性能特性
    /// - 无规则编译开销：直接使用已编译的 `CompiledBundle`；
    /// - Arc封装：编译包和缓存均通过Arc共享，多实例无重复初始化成本。
    /// 
    /// # 参数
    /// - `compiled_bundle`: 已编译的规则包（`CompiledBundle` 实例）；
    /// - `rule_index`: 规则库索引（编译规则包对应的索引，用于调试/扩展）；
    /// - `config`: 规则配置，控制检测行为、规则过滤等。
    /// 
    /// # 返回值
    /// 成功返回检测器实例，失败返回 `RswResult` 封装的错误（如AC缓存初始化失败）。
    pub fn with_compiled_lib(
        compiled_bundle: CompiledBundle,
        rule_index: RuleLibraryIndex,
        config: RuleConfig,
    ) -> RswResult<Self> {
        // 基于已编译规则包创建AC自动机缓存（无编译开销）
        let ac_cache = AcAutomatonCache::new(&compiled_bundle).map_err(CoreError::from)?;

        // 构建运行时规则库（仅移动 Arc 指针，无数据拷贝）
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

    /// 通用入口：创建技术检测器
    /// 
    /// 最常用的创建方式，根据 `RuleConfig` 中的 `RuleOrigin` 自动选择规则加载/创建方式，
    /// 支持所有规则来源（内置、本地文件、远程官方、远程自定义），简化外部调用逻辑。
    /// 
    /// # 规则来源说明
    /// 1. `Embedded`: 使用内置预编译规则（需开启 `embedded-rules` 特性）；
    /// 2. `LocalFile`: 从本地文件加载规则并编译；
    /// 3. `RemoteOfficial`: 从官方远程地址加载规则并编译；
    /// 4. `RemoteCustom`: 从自定义远程地址加载规则并编译。
    /// 
    /// # 异步说明
    /// 标记为 `async` 是因为远程规则加载需要网络IO，本地/内置规则加载为同步逻辑，
    /// 统一异步接口避免多态调用复杂度。
    /// 
    /// # 参数
    /// - `config`: 规则配置，包含规则来源、检测配置等核心信息。
    /// 
    /// # 返回值
    /// 成功返回检测器实例，失败返回 `RswResult` 封装的错误（如规则加载失败、编译失败、网络错误等）。
    pub async fn new(config: RuleConfig) -> RswResult<Self> {
        match &config.origin {
            // Embedded模式 - 特性守卫 + 降级处理
            RuleOrigin::Embedded => {
                #[cfg(feature = "embedded-rules")]
                {
                    Self::with_embedded_rules(config)
                }
                // 关闭特性时，返回明确的错误
                #[cfg(not(feature = "embedded-rules"))]
                {
                    return Err(RswappalyzerError::FeatureDisabled(
                        "embedded-rules feature is disabled, cannot use embedded rule library. Please enable this feature or use local/remote rules.".to_string()
                    ));
                }
            }

            // 运行时加载模式（本地/远程规则）
            RuleOrigin::LocalFile(_) | RuleOrigin::RemoteOfficial | RuleOrigin::RemoteCustom(_) => {
                // 1. 加载规则库（优先从缓存加载）
                let rule_loader = RuleLoader::new();
                let rule_lib = rule_loader.load(&config).await?;

                // 2. 构建规则库索引
                let rule_index = RuleLibraryIndex::from_rule_library(&rule_lib)?;

                // 3. 编译规则库
                let compiled_bundle = RuleIndexer::build_compiled_library(
                    &rule_index,
                    Some("data/categories_data.json"),
                )?;

                let ac_cache = AcAutomatonCache::new(&compiled_bundle).map_err(CoreError::from)?;

                // 构建运行时规则库
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
        }
    }
}