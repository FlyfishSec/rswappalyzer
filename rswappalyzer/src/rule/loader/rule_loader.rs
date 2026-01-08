use log::{debug, warn};
#[cfg(feature = "remote-loader")]
use reqwest::Client;
use rswappalyzer_engine::source::WappalyzerParser;
use rswappalyzer_engine::{RuleLibrary, RuleProcessor};
use std::fs;
use std::path::Path;

use crate::error::{RswResult, RswappalyzerError};
use crate::{RuleCacheManager, RuleConfig, RuleOrigin};

/// 规则加载器
/// 核心职责：根据不同规则源（内置/本地/远程）加载并处理Wappalyzer规则库
#[derive(Default)]
pub struct RuleLoader {
    /// ETag管理器：负责ETag记录的加载/更新/保存
    #[cfg(feature = "remote-loader")]
    etag_manager: crate::rule::loader::EtagManager,
    /// 远程规则获取器：负责网络请求和重试逻辑
    #[cfg(feature = "remote-loader")]
    remote_fetcher: crate::rule::loader::RemoteRuleFetcher,
    /// 规则处理器：负责规则清洗/拆分/统计
    rule_processor: RuleProcessor,
}

impl RuleLoader {
    /// 创建规则加载器实例
    pub fn new() -> Self {
        Self::default()
    }

    /// 加载内置规则（空实现，仅保留接口兼容性）
    /// 返回：默认空规则库
    pub fn load_embedded(&self) -> RswResult<RuleLibrary> {
        Ok(RuleLibrary::default())
    }

    /// 规则加载核心入口（单规则源加载）
    /// 参数：
    /// - config: 规则配置
    /// 返回：加载完成的规则库 | 加载错误
    pub async fn load(&self, config: &RuleConfig) -> RswResult<RuleLibrary> {
        match &config.origin {
            RuleOrigin::Embedded => self.load_embedded(),
            RuleOrigin::LocalFile(path) => self.load_local_file(config, path).await,
            RuleOrigin::RemoteOfficial | RuleOrigin::RemoteCustom(_) => {
                self.load_remote_rules(config).await
            }
        }
    }

    /// 通用缓存加载逻辑（本地/远程规则复用）
    /// 参数：
    /// - config: 规则配置
    /// 返回：缓存规则库（None表示加载失败）
    async fn load_from_cache_unified(&self, config: &RuleConfig) -> Option<RuleLibrary> {
        let cache_path = config.get_cache_file_path();
        match RuleCacheManager::load_from_cache(config) {
            Ok(rule_lib) => {
                debug!(
                    "Loaded rules from cache successfully: {}",
                    cache_path.display()
                );
                Some(rule_lib)
            }
            Err(e) => {
                warn!(
                    "Failed to load rules from cache: {} - {}",
                    cache_path.display(),
                    e
                );
                None
            }
        }
    }

    /// 通用缓存保存逻辑（本地/远程规则复用）
    /// 参数：
    /// - config: 规则配置
    /// - rule_lib: 待缓存的规则库
    async fn save_to_cache_unified(&self, config: &RuleConfig, rule_lib: &RuleLibrary) {
        let cache_path = config.get_cache_file_path();
        if let Err(e) = RuleCacheManager::save_to_cache(config, rule_lib) {
            warn!("Failed to cache rules: {} - {}", cache_path.display(), e);
        } else {
            debug!("Rules cached successfully to: {}", cache_path.display());
        }
    }

    /// 加载本地规则文件
    /// 逻辑：缓存优先 → 读取原始文件 → 解析清洗 → 缓存保存
    /// 参数：
    /// - config: 规则配置
    /// - path: 本地规则文件路径
    /// 返回：处理后的规则库 | 加载错误
    async fn load_local_file(&self, config: &RuleConfig, path: &Path) -> RswResult<RuleLibrary> {
        // 1. 优先从缓存加载
        if let Some(cached_lib) = self.load_from_cache_unified(config).await {
            return Ok(cached_lib);
        }
        warn!("Local cache not found, reading raw rule file: {:?}", path);

        // 2. 读取并解析原始规则文件
        let raw_content = fs::read_to_string(path).map_err(|e| {
            RswappalyzerError::RuleLoadError(format!(
                "Failed to read raw rule file: {} - {}",
                path.display(),
                e
            ))
        })?;

        let parser = WappalyzerParser::default();
        let raw_lib = parser.parse_to_rule_lib(&raw_content).map_err(|e| {
            RswappalyzerError::RuleLoadError(format!("Failed to parse rules: {}", e))
        })?;

        // 3. 清洗拆分规则并缓存
        let cleaned_lib = self.rule_processor.clean_and_split_rules(&raw_lib)?;
        self.save_to_cache_unified(config, &cleaned_lib).await;

        Ok(cleaned_lib)
    }

    /// 加载远程规则（仅remote-loader特性启用时生效）
    /// 核心逻辑：ETag校验 → 缓存优先/远程拉取 → 规则处理 → 缓存更新
    /// 参数：
    /// - config: 规则配置
    /// 返回：处理后的规则库 | 加载错误
    #[cfg(feature = "remote-loader")]
    async fn load_remote_rules(&self, config: &RuleConfig) -> RswResult<RuleLibrary> {
        // 1. 校验远程配置是否存在
        let remote_opts = config.remote_options.as_ref().ok_or_else(|| {
            RswappalyzerError::RuleLoadError("Missing remote network configuration".into())
        })?;

        // 2. 解析远程规则源URL和名称
        let (remote_url, source_identifier) = match &config.origin {
        RuleOrigin::RemoteOfficial => (
            "https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/refs/heads/main/fingerprints_data.json",
            "wappalyzergo_official"
        ),
        RuleOrigin::RemoteCustom(custom_url) => (custom_url.as_str(), "wappalyzer_custom"),
        _ => return Err(RswappalyzerError::RuleLoadError("Not a remote rule source".into())),
    };

        // 3. 优先尝试加载缓存（核心逻辑分支点）
        let cached_lib = self.load_from_cache_unified(config).await;
        if let Some(lib) = cached_lib {
            // 3.1 check_update=false 且缓存存在：直接返回缓存，不发起任何网络请求
            if !config.options.check_update {
                debug!("check_update is false and cache exists, skip all network requests");
                return Ok(lib);
            }
            // 3.2 check_update=true 且缓存存在：继续执行ETag检测流程
            debug!("check_update is true, proceed to ETag check");
        } else {
            warn!("Cache not found, need to fetch remote rules completely");
        }

        // 4. 创建HTTP客户端（带超时配置）
        let client = Client::builder()
            .timeout(remote_opts.timeout)
            .build()
            .map_err(|e| {
                RswappalyzerError::RuleLoadError(format!("Failed to build HTTP client: {}", e))
            })?;

        // 5. 根据check_update决定是否执行ETag检测
        let cleaned_rule_lib = if config.options.check_update {
            // 5.1 check_update=true：完整ETag检测流程（原有逻辑）
            let mut etag_records = self.etag_manager.load_etag_records(config)?;
            let remote_etag = self
                .remote_fetcher
                .get_remote_etag(&client, remote_url, &remote_opts.retry)
                .await?;

            match remote_etag {
                None => {
                    warn!("Remote ETag not found, force fetching latest rules");
                    let raw_lib = self
                        .remote_fetcher
                        .fetch_wappalyzer_rules(&client, remote_url, &remote_opts.retry)
                        .await?;
                    let cleaned_lib = self.rule_processor.clean_and_split_rules(&raw_lib)?;
                    self.save_to_cache_unified(config, &cleaned_lib).await;
                    cleaned_lib
                }
                Some(etag) => {
                    let local_etag_record = self
                        .etag_manager
                        .find_local_etag(config, source_identifier)?;
                    let use_local_cache = self
                        .remote_fetcher
                        .should_use_local_file(&local_etag_record, &etag);

                    if use_local_cache {
                        debug!("Rule library is up-to-date, using local cache");
                        self.load_from_cache_unified(config).await.ok_or_else(|| {
                            RswappalyzerError::RuleLoadError(
                                "Local cache missing but ETag matches".into(),
                            )
                        })?
                    } else {
                        debug!("New rule library detected, fetching remote rules");
                        let raw_lib = self
                            .remote_fetcher
                            .fetch_wappalyzer_rules(&client, remote_url, &remote_opts.retry)
                            .await?;
                        let cleaned_lib = self.rule_processor.clean_and_split_rules(&raw_lib)?;

                        self.save_to_cache_unified(config, &cleaned_lib).await;

                        self.etag_manager.upsert_and_save_etag(
                            config,
                            &mut etag_records,
                            source_identifier,
                            etag,
                            config.get_cache_file_path().to_string_lossy().to_string(),
                        )?;

                        cleaned_lib
                    }
                }
            }
        } else {
            // 5.2 check_update=false：仅缓存失效时发起完整请求（无ETag检测）
            debug!("check_update is false, fetch full rules without ETag check");
            let raw_lib = self
                .remote_fetcher
                .fetch_wappalyzer_rules(&client, remote_url, &remote_opts.retry)
                .await?;
            let cleaned_lib = self.rule_processor.clean_and_split_rules(&raw_lib)?;
            self.save_to_cache_unified(config, &cleaned_lib).await;
            cleaned_lib
        };

        Ok(cleaned_rule_lib)
    }

    /// 非remote-loader模式下的远程加载逻辑（直接返回错误）
    #[cfg(not(feature = "remote-loader"))]
    async fn load_remote_rules(&self, _config: &RuleConfig) -> RswResult<RuleLibrary> {
        Err(RswappalyzerError::RuleLoadError(
            "Please enable 'remote-loader' feature to load remote rules".into(),
        ))
    }

    /// 调试方法：统计脚本规则数量
    /// 参数：
    /// - rule_lib: 规则库实例
    pub fn debug_count_script_rules(&self, rule_lib: &RuleLibrary) {
        self.rule_processor.debug_count_script_rules(rule_lib);
    }
}

/// 异步任务错误转换（JoinError → RswappalyzerError）
#[cfg(feature = "remote-loader")]
impl From<tokio::task::JoinError> for RswappalyzerError {
    fn from(err: tokio::task::JoinError) -> Self {
        RswappalyzerError::AsyncTaskError(format!("Async task failed: {}", err))
    }
}
