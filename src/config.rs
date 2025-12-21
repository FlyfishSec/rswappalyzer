//! 全局配置管理,存储所有可配置项

use std::path::PathBuf;

/// 全局配置
#[derive(Debug, Clone)]
pub struct GlobalConfig {
    // 规则缓存路径
    pub rule_cache_path: PathBuf,
    // GitHub代理URL
    pub gh_proxy_url: String,
    // 超时配置（单位：秒）
    pub http_timeout: u64,
    // 是否启用详细日志
    pub verbose: bool,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            rule_cache_path: PathBuf::from("wappalyzer_rules.mp"),
            gh_proxy_url: "https://ghfast.top/".to_string(),
            http_timeout: 30,
            verbose: false,
        }
    }
}

/// 配置管理器（单例）
pub struct ConfigManager;

impl ConfigManager {
    /// 获取默认配置
    pub fn get_default() -> GlobalConfig {
        GlobalConfig::default()
    }

    /// 自定义配置
    pub fn custom() -> CustomConfigBuilder {
        CustomConfigBuilder::new()
    }
}

/// 配置构建器（便于自定义配置）
#[derive(Debug, Clone)]
pub struct CustomConfigBuilder {
    config: GlobalConfig,
}

impl CustomConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: GlobalConfig::default(),
        }
    }

    pub fn rule_cache_path(mut self, path: PathBuf) -> Self {
        self.config.rule_cache_path = path;
        self
    }

    pub fn gh_proxy_url(mut self, url: String) -> Self {
        self.config.gh_proxy_url = url;
        self
    }

    pub fn http_timeout(mut self, timeout: u64) -> Self {
        self.config.http_timeout = timeout;
        self
    }

    pub fn verbose(mut self, verbose: bool) -> Self {
        self.config.verbose = verbose;
        self
    }

    pub fn build(self) -> GlobalConfig {
        self.config
    }
}