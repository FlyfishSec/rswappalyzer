//! 全局规则配置管理

use std::hash::Hash;
use std::hash::Hasher;
use std::{hash::DefaultHasher, path::PathBuf, time::Duration};

pub use rswappalyzer_engine::RegexCacheConfig;
pub use rswappalyzer_engine::regex_cache_config::RegexCache;

/// 规则来源
#[derive(Debug, Clone, PartialEq)]
pub enum RuleSource {
    Embedded,             // 内置规则（编译期 embed）
    LocalFile(PathBuf),   // 本地文件规则（运行时）
    RemoteOfficial,       // 官方远程规则源
    RemoteCustom(String), // 自定义远程 URL（官方格式要求）
}

/// 规则阶段（明确区分原始/已编译状态）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleStage {
    Raw,      // 原始规则（需要解析 / 编译）
    Compiled, // 已编译产物（可直接使用）
    Cached,   // 缓存的规则
}

/// 规则来源+阶段（核心抽象：组合语义）
#[derive(Debug, Clone)]
pub struct RuleOrigin {
    pub source: RuleSource,
    pub stage: RuleStage,
}

impl RuleOrigin {
    // 向后兼容：提供原有 RuleOrigin 变体的构造方法
    pub fn embedded() -> Self {
        Self {
            source: RuleSource::Embedded,
            stage: RuleStage::Compiled, // 内置规则默认是已编译状态
        }
    }

    pub fn local_file(path: impl Into<PathBuf>) -> Self {
        Self {
            source: RuleSource::LocalFile(path.into()),
            stage: RuleStage::Raw, // 本地文件默认是原始规则
        }
    }

    pub fn remote_official() -> Self {
        Self {
            source: RuleSource::RemoteOfficial,
            stage: RuleStage::Raw, // 远程规则默认是原始规则
        }
    }

    pub fn remote_custom(url: impl Into<String>) -> Self {
        Self {
            source: RuleSource::RemoteCustom(url.into()),
            stage: RuleStage::Raw, // 自定义远程规则默认是原始规则
        }
    }

    // 显式指定本地已编译文件的构造方法
    pub fn local_compiled_file(path: impl Into<PathBuf>) -> Self {
        Self {
            source: RuleSource::LocalFile(path.into()),
            stage: RuleStage::Compiled,
        }
    }

    // 本地缓存规则文件专属构造器（显式指定 Cached 阶段）
    pub fn local_cached_file(path: impl Into<PathBuf>) -> Self {
        Self {
            source: RuleSource::LocalFile(path.into()),
            stage: RuleStage::Cached, // 明确标记为缓存阶段
        }
    }
}

/// 规则加载方式
#[derive(Debug, Clone)]
pub enum RuleLoadMethod {
    Embedded,          // 编译期 embed（固定）
    CacheDir(PathBuf), // 外部缓存目录（本地/远程规则）
}

/// 网络加载相关选项
#[derive(Debug, Clone)]
pub struct RemoteOptions {
    pub urls: Vec<String>,  // URL 列表
    pub timeout: Duration,  // HTTP 超时
    pub retry: RetryPolicy, // 重试策略
}

/// 重试策略
#[derive(Debug, Clone)]
pub enum RetryPolicy {
    Never,     // 不重试
    Times(u8), // 固定次数重试（不含第一次）
}

/// 核心规则选项
#[derive(Debug, Clone)]
pub struct RuleOptions {
    /// 仅对远程规则有效：是否在启动时检查更新
    pub check_update: bool,
    /// 规则缓存目录（远程规则 / 构建产物等）
    pub cache_dir: PathBuf,
    /// 可自定义缓存文件名
    pub cache_file_name: Option<PathBuf>,
}

impl Default for RuleOptions {
    fn default() -> Self {
        Self {
            check_update: true,
            cache_dir: PathBuf::from(".cache/rswappalyzer"),
            cache_file_name: None, // 默认不指定
        }
    }
}

/// 完整规则配置
#[derive(Debug, Clone)]
pub struct RuleConfig {
    pub origin: RuleOrigin,
    pub load_method: RuleLoadMethod,
    pub options: RuleOptions,
    pub remote_options: Option<RemoteOptions>,
    /// 正则缓存配置（创建实例时使用，默认值：RegexCacheConfig::default()）
    pub regex_cache_config: RegexCacheConfig,
    // /// 可选的共享正则缓存实例（传则复用，不传则用 regex_cache_config 创建新实例）
    // pub regex_cache_instance: Option<Arc<RegexCache>>,
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            origin: RuleOrigin::embedded(),
            load_method: RuleLoadMethod::Embedded,
            options: RuleOptions::default(),
            remote_options: None,
            regex_cache_config: RegexCacheConfig::default(),
            //regex_cache_instance: None, // 默认不复用正则缓存实例
        }
    }
}

impl RuleConfig {
    /// 构建空配置（用于字节传入场景，仅记录元信息）
    pub fn empty() -> Self {
        Self {
            origin: RuleOrigin::embedded(), // 标记为嵌入式（仅元信息）
            load_method: RuleLoadMethod::Embedded,
            options: RuleOptions {
                check_update: false, // 字节规则无需更新
                ..RuleOptions::default()
            },
            remote_options: None,
            regex_cache_config: RegexCacheConfig::default(),
            //regex_cache_instance: None,
        }
    }

    /// 内置规则
    pub fn embedded() -> Self {
        Self::default()
    }

    /// 本地规则文件
    pub fn local_file(path: impl Into<PathBuf>) -> Self {
        let path_buf = path.into();
        let cache_dir = RuleOptions::default().cache_dir;
        Self {
            origin: RuleOrigin::local_file(path_buf),
            load_method: RuleLoadMethod::CacheDir(cache_dir),
            options: RuleOptions::default(),
            remote_options: None,
            regex_cache_config: RegexCacheConfig::default(),
            // regex_cache_instance: None,
        }
    }

    /// 带缓存配置的本地文件
    pub fn local_file_with_regex_cache_config(
        path: impl Into<PathBuf>,
        cache_settings: RegexCacheConfig,
    ) -> Self {
        let mut config = Self::local_file(path);
        config.regex_cache_config = cache_settings;
        config
    }

    /// 本地已编译规则文件
    pub fn local_compiled_file(path: impl Into<PathBuf>) -> Self {
        let path_buf = path.into();
        let cache_dir = RuleOptions::default().cache_dir;
        Self {
            origin: RuleOrigin::local_compiled_file(path_buf),
            load_method: RuleLoadMethod::CacheDir(cache_dir),
            options: RuleOptions {
                check_update: false, // 已编译文件无需检查更新
                ..RuleOptions::default()
            },
            remote_options: None,
            regex_cache_config: RegexCacheConfig::default(),
            // regex_cache_instance: None,
        }
    }

    pub fn local_cached_file(path: impl Into<PathBuf>) -> Self {
        let path_buf = path.into();
        let cache_dir = RuleOptions::default().cache_dir;
        Self {
            origin: RuleOrigin::local_cached_file(path_buf),
            load_method: RuleLoadMethod::CacheDir(cache_dir),
            options: RuleOptions {
                check_update: false, // 缓存文件无需检查更新（框架生成的静态文件）
                ..RuleOptions::default()
            },
            remote_options: None,
            regex_cache_config: RegexCacheConfig::default(),
            // regex_cache_instance: None,
        }
    }

    /// 官方远程规则源
    pub fn remote_official(timeout: Duration, retry: RetryPolicy) -> Self {
        let url = "https://official.source/rules.json".to_string();
        let cache_dir = RuleOptions::default().cache_dir;
        Self {
            origin: RuleOrigin::remote_official(),
            load_method: RuleLoadMethod::CacheDir(cache_dir.clone()),
            options: RuleOptions::default(),
            remote_options: Some(RemoteOptions {
                urls: vec![url],
                timeout,
                retry,
            }),
            regex_cache_config: RegexCacheConfig::default(),
            // regex_cache_instance: None,
        }
    }

    /// 自定义远程规则源
    pub fn remote_custom(url: impl Into<String>, timeout: Duration, retry: RetryPolicy) -> Self {
        let url = url.into();
        let cache_dir = RuleOptions::default().cache_dir;
        Self {
            origin: RuleOrigin::remote_custom(url.clone()),
            load_method: RuleLoadMethod::CacheDir(cache_dir.clone()),
            options: RuleOptions::default(),
            remote_options: Some(RemoteOptions {
                urls: vec![url],
                timeout,
                retry,
            }),
            regex_cache_config: RegexCacheConfig::default(),
            // regex_cache_instance: None,
        }
    }

    /// 根据规则源生成缓存文件的完整路径（目录 + 文件名）
    pub fn get_cache_file_path(&self) -> PathBuf {
        if let Some(ref file_name) = self.options.cache_file_name {
            return self.options.cache_dir.join(file_name);
        }

        let file_name = match &self.origin.source {
            RuleSource::Embedded => {
                // 内置规则返回占位 PathBuf
                PathBuf::from("embedded_rules_unsupported.json")
            }
            RuleSource::LocalFile(_) => {
                // 区分原始/编译文件的默认命名
                match self.origin.stage {
                    RuleStage::Raw => PathBuf::from("rswappalyzer_rules_cache.json"),
                    RuleStage::Compiled => PathBuf::from("compiled_rules_unsupported.json"),
                    RuleStage::Cached => PathBuf::from("cached_rules_unsupported.json"), // 占位文件名（无需缓存）
                }
            }
            RuleSource::RemoteOfficial => PathBuf::from("official_rules.json"),
            RuleSource::RemoteCustom(url) => {
                // 1. 生成固定哈希：相同 URL → 相同哈希值 → 相同文件名（实现覆盖）
                let mut hasher = DefaultHasher::new();
                url.hash(&mut hasher);
                let hash = hasher.finish(); // u64 哈希值，相同 URL 永远返回相同值

                // 2. 拼接为 PathBuf（统一返回类型）
                PathBuf::from(format!("custom_{:x}.json", hash))
            }
        };

        // 最终返回：缓存目录 + 文件名（PathBuf 拼接）
        self.options.cache_dir.join(file_name)
    }

    /// 链式设置缓存配置
    pub fn with_regex_cache_config(mut self, cache_settings: RegexCacheConfig) -> Self {
        self.regex_cache_config = cache_settings;
        self
    }

    // // 共享实例方法
    // pub fn with_regex_cache_instance(mut self, instance: Arc<RegexCache>) -> Self {
    //     self.regex_cache_instance = Some(instance);
    //     self
    // }

    // pub fn resolve_regex_cache(&self) -> Arc<RegexCache> {
    //     match self.regex_cache_instance.as_ref() {
    //         Some(instance) => instance.clone(),
    //         None => Arc::new(RegexCache::new(self.regex_cache_config.to_engine_config())),
    //     }
    // }
}

/// 自定义构建器（链式 API）
#[derive(Debug, Clone)]
pub struct CustomConfigBuilder {
    config: RuleConfig,
}

impl CustomConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: RuleConfig::default(),
        }
    }

    /// 内部方法：根据 origin 决定 load_method
    fn apply_load_method(&mut self) {
        let cache_dir = self.config.options.cache_dir.clone();
        self.config.load_method = match &self.config.origin.source {
            RuleSource::Embedded => RuleLoadMethod::Embedded,
            RuleSource::LocalFile(_) => RuleLoadMethod::CacheDir(cache_dir),
            RuleSource::RemoteOfficial => RuleLoadMethod::CacheDir(cache_dir),
            RuleSource::RemoteCustom(_) => RuleLoadMethod::CacheDir(cache_dir),
        };
    }

    pub fn check_update(mut self, check: bool) -> Self {
        self.config.options.check_update = check;
        self
    }

    pub fn cache_dir(mut self, path: PathBuf) -> Self {
        self.config.options.cache_dir = path;
        self
    }

    /// 链式api：设置缓存文件名
    pub fn cache_file_name<P: Into<PathBuf>>(mut self, file_name: P) -> Self {
        self.config.options.cache_file_name = Some(file_name.into());
        self
    }

    /// 链式api：设置规则来源
    pub fn origin(mut self, origin: RuleOrigin) -> Self {
        self.config.origin = origin;
        self.apply_load_method();
        self
    }

    /// 显式设置规则阶段
    pub fn stage(mut self, stage: RuleStage) -> Self {
        self.config.origin.stage = stage;
        self
    }

    /// 快速设置本地已编译文件
    pub fn local_compiled_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.origin = RuleOrigin::local_compiled_file(path);
        self.config.options.check_update = false;
        self.apply_load_method();
        self
    }

    // 快速设置本地缓存规则文件
    pub fn local_cached_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.origin = RuleOrigin::local_cached_file(path);
        self.config.options.check_update = false;
        self.apply_load_method();
        self
    }

    pub fn remote_options(mut self, remote_opts: RemoteOptions) -> Self {
        self.config.remote_options = Some(remote_opts);
        self
    }

    /// 链式设置正则缓存配置
    pub fn regex_cache_config(mut self, cache_settings: RegexCacheConfig) -> Self {
        self.config.regex_cache_config = cache_settings;
        self
    }

    /// 快速设置正则缓存大小和TTL
    pub fn regex_cache_params(mut self, max_size: usize, ttl_seconds: u64) -> Self {
        self.config.regex_cache_config = RegexCacheConfig::new(max_size, ttl_seconds);
        self
    }

    // // 共享实例方法
    // pub fn regex_cache_instance(mut self, instance: Arc<RegexCache>) -> Self {
    //     self.config.regex_cache_instance = Some(instance);
    //     self
    // }

    pub fn build(mut self) -> RuleConfig {
        self.apply_load_method();
        self.config
    }
}
