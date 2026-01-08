//! 全局规则配置管理

use std::hash::Hasher;
use std::hash::Hash;
use std::{hash::DefaultHasher, path::PathBuf, time::Duration};

/// 规则来源
#[derive(Debug, Clone)]
pub enum RuleOrigin {
    Embedded,             // 内置规则（编译期 embed）
    LocalFile(PathBuf),   // 本地文件规则（运行时）
    RemoteOfficial,       // 官方远程规则源
    RemoteCustom(String), // 自定义远程 URL（官方格式要求）
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
}

impl Default for RuleOptions {
    fn default() -> Self {
        Self {
            check_update: true,
            cache_dir: PathBuf::from(".cache/rswappalyzer"),
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
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            origin: RuleOrigin::Embedded,
            load_method: RuleLoadMethod::Embedded,
            options: RuleOptions::default(),
            remote_options: None,
        }
    }
}

impl RuleConfig {
    /// 内置规则
    pub fn embedded() -> Self {
        Self::default()
    }

    /// 本地规则文件（缓存目录仍指向配置的目录，仅规则源为本地文件）
    pub fn local_file(path: impl Into<PathBuf>) -> Self {
        let path_buf = path.into();
        let cache_dir = RuleOptions::default().cache_dir;
        Self {
            origin: RuleOrigin::LocalFile(path_buf),
            load_method: RuleLoadMethod::CacheDir(cache_dir),
            options: RuleOptions::default(),
            remote_options: None,
        }
    }

    /// 官方远程规则源
    pub fn remote_official(timeout: Duration, retry: RetryPolicy) -> Self {
        let url = "https://official.source/rules.json".to_string();
        let cache_dir = RuleOptions::default().cache_dir;
        Self {
            origin: RuleOrigin::RemoteOfficial,
            load_method: RuleLoadMethod::CacheDir(cache_dir.clone()),
            options: RuleOptions::default(),
            remote_options: Some(RemoteOptions {
                urls: vec![url],
                timeout,
                retry,
            }),
        }
    }

    /// 自定义远程规则源
    pub fn remote_custom(url: impl Into<String>, timeout: Duration, retry: RetryPolicy) -> Self {
        let url = url.into();
        let cache_dir = RuleOptions::default().cache_dir;
        Self {
            origin: RuleOrigin::RemoteCustom(url.clone()),
            load_method: RuleLoadMethod::CacheDir(cache_dir.clone()),
            options: RuleOptions::default(),
            remote_options: Some(RemoteOptions {
                urls: vec![url],
                timeout,
                retry,
            }),
        }
    }

    /// 根据规则源生成缓存文件的完整路径（目录 + 文件名）
    pub fn get_cache_file_path(&self) -> PathBuf {
        let file_name = match &self.origin {
            RuleOrigin::Embedded => {
                // 内置规则返回占位 PathBuf
                PathBuf::from("embedded_rules_unsupported.json")
            }
            RuleOrigin::LocalFile(_) => {
                // 统一返回 PathBuf（解决类型不匹配）
                PathBuf::from("rswappalyzer_rules_cache.json")
            }
            RuleOrigin::RemoteOfficial => {
                // 统一返回 PathBuf
                PathBuf::from("official_rules.json")
            }
            RuleOrigin::RemoteCustom(url) => {
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
        self.config.load_method = match &self.config.origin {
            RuleOrigin::Embedded => RuleLoadMethod::Embedded,
            RuleOrigin::LocalFile(_) => RuleLoadMethod::CacheDir(cache_dir),
            RuleOrigin::RemoteOfficial => RuleLoadMethod::CacheDir(cache_dir),
            RuleOrigin::RemoteCustom(_) => RuleLoadMethod::CacheDir(cache_dir),
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

    pub fn origin(mut self, origin: RuleOrigin) -> Self {
        self.config.origin = origin;
        self.apply_load_method();
        self
    }

    pub fn remote_options(mut self, remote_opts: RemoteOptions) -> Self {
        self.config.remote_options = Some(remote_opts);
        self
    }

    pub fn build(mut self) -> RuleConfig {
        self.apply_load_method();
        self.config
    }
}
