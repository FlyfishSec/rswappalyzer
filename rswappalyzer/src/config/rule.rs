//! 全局规则配置管理

use std::{path::PathBuf, time::Duration};

/// 规则来源
#[derive(Debug, Clone)]
pub enum RuleOrigin {
    Embedded,                  // 内置规则（编译期 embed）
    LocalFile(PathBuf),        // 本地文件规则（运行时）
    RemoteOfficial,            // 官方远程规则源
    RemoteCustom(String),      // 自定义远程 URL（官方格式要求）
}

/// 规则加载方式
#[derive(Debug, Clone)]
pub enum RuleLoadMethod {
    Embedded,             // 编译期 embed（固定）
    CacheFile(PathBuf),   // 外部缓存文件（本地/远程规则）
}

/// 网络加载相关选项
#[derive(Debug, Clone)]
pub struct RemoteOptions {
    pub urls: Vec<String>,          // URL 列表
    pub timeout: Duration,          // HTTP 超时
    pub retry: RetryPolicy,         // 重试策略
}

/// 重试策略
#[derive(Debug, Clone)]
pub enum RetryPolicy {
    Never,              // 不重试
    Times(u8),          // 固定次数重试（不含第一次）
}

/// 核心规则选项
#[derive(Debug, Clone)]
pub struct RuleOptions {
    /// 仅对远程规则有效：是否在启动时检查更新
    pub check_update: bool,     
    /// 缓存路径（用于远程规则缓存）
    pub cache_path: PathBuf,    
}

impl Default for RuleOptions {
    fn default() -> Self {
        Self {
            check_update: true,  // 默认远程规则检查更新
            cache_path: PathBuf::from("rswappalyzer_rules.json"),
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

    /// 本地规则文件
    pub fn local_file(path: impl Into<PathBuf>) -> Self {
        let path_buf = path.into();
        Self {
            origin: RuleOrigin::LocalFile(path_buf.clone()),
            load_method: RuleLoadMethod::CacheFile(path_buf),
            options: RuleOptions::default(),
            remote_options: None,
        }
    }

    /// 官方远程规则源
    pub fn remote_official(timeout: Duration, retry: RetryPolicy) -> Self {
        let url = "https://official.source/rules.json".to_string();
        let cache_path = PathBuf::from("rswappalyzer_rules.json");
        Self {
            origin: RuleOrigin::RemoteOfficial,
            load_method: RuleLoadMethod::CacheFile(cache_path.clone()),
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
        let cache_path = PathBuf::from("rswappalyzer_rules.mp");
        Self {
            origin: RuleOrigin::RemoteCustom(url.clone()),
            load_method: RuleLoadMethod::CacheFile(cache_path.clone()),
            options: RuleOptions::default(),
            remote_options: Some(RemoteOptions {
                urls: vec![url],
                timeout,
                retry,
            }),
        }
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
        self.config.load_method = match &self.config.origin {
            RuleOrigin::Embedded => RuleLoadMethod::Embedded,
            RuleOrigin::LocalFile(p) => RuleLoadMethod::CacheFile(p.clone()),
            RuleOrigin::RemoteOfficial => RuleLoadMethod::CacheFile(PathBuf::from("rswappalyzer_rules.json")),
            RuleOrigin::RemoteCustom(_) => RuleLoadMethod::CacheFile(PathBuf::from("rswappalyzer_rules.mp")),
        };
    }

    pub fn check_update(mut self, check: bool) -> Self {
        self.config.options.check_update = check;
        self
    }

    pub fn cache_path(mut self, path: PathBuf) -> Self {
        self.config.options.cache_path = path;
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
