use crate::error::{RswResult, RswappalyzerError};
use crate::rule::core::RuleLibrary;
use crate::rule::loader::{EtagManager, RemoteRuleFetcher, RulePathManager, RuleProcessor};
use crate::{RuleConfig, RuleOrigin};
#[cfg(feature = "remote-loader")]
use reqwest::Client;

#[derive(Default)]
pub struct RuleLoader {
    #[allow(dead_code)]
    path_manager: RulePathManager,
    #[allow(dead_code)]
    etag_manager: EtagManager,
    #[allow(dead_code)]
    remote_fetcher: RemoteRuleFetcher,
    rule_processor: RuleProcessor,
}

impl RuleLoader {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn load(&self, config: &RuleConfig) -> RswResult<RuleLibrary> {
        self.load_from_source(&config.origin, config).await
    }

    async fn load_from_source(
        &self,
        source: &RuleOrigin,
        config: &RuleConfig,
    ) -> RswResult<RuleLibrary> {
        match source {
            RuleOrigin::Embedded => self.rule_processor.load_embedded(),

            RuleOrigin::LocalFile(path) => self
                .rule_processor
                .load_from_cache(config)
                .await
                .ok_or_else(|| {
                    RswappalyzerError::RuleLoadError(format!(
                        "本地路径[{}]缓存规则加载失败或无缓存",
                        path.display()
                    ))
                }),

            RuleOrigin::RemoteOfficial => self.load_remote_rules(config, None).await,

            RuleOrigin::RemoteCustom(url) => self.load_remote_rules(config, Some(url)).await,
        }
    }
    #[cfg(feature = "remote-loader")]
    async fn load_remote_rules(
        &self,
        config: &RuleConfig,
        override_url: Option<&str>,
    ) -> RswResult<RuleLibrary> {
        let remote_opts = config
            .remote_options
            .as_ref()
            .ok_or_else(|| RswappalyzerError::RuleLoadError("缺少远程配置".into()))?;

        let url = override_url.unwrap_or(&remote_opts.urls[0]);
        let client = build_reqwest_client(remote_opts)?;

        self.load_remote_with_client(config, &client, url).await
    }

    #[cfg(not(feature = "remote-loader"))]
    async fn load_remote_rules(
        &self,
        _config: &RuleConfig,
        _override_url: Option<&str>,
    ) -> RswResult<RuleLibrary> {
        Err(RswappalyzerError::RuleLoadError(
            "remote-loader feature 未启用".into(),
        ))
    }

    #[cfg(feature = "remote-loader")]
    async fn load_remote_with_client(
        &self,
        config: &RuleConfig,
        client: &Client,
        base_url: &str,
    ) -> RswResult<RuleLibrary> {
        let remote_opts = config
            .remote_options
            .as_ref()
            .ok_or_else(|| RswappalyzerError::RuleLoadError("远程规则缺少网络配置项".into()))?;
        let retry_policy = &remote_opts.retry;
        let etag_total_record = self.etag_manager.load_etag_records(config)?;
        let remote_sources = self.remote_fetcher.build_remote_sources_from_url(base_url);
        let mut rule_lib: Option<RuleLibrary> = None;

        for source in &remote_sources {
            let remote_etag = match self
                .remote_fetcher
                .get_remote_etag(client, &source.raw_url, retry_policy)
                .await
            {
                Ok(Some(etag)) => etag,
                _ => continue,
            };

            let local_etag_record = self.etag_manager.find_local_etag(config, &source.name)?;
            let use_local_file = self
                .remote_fetcher
                .should_use_local_file(&local_etag_record, &remote_etag);

            let current_rule_lib = if use_local_file {
                self.remote_fetcher
                    .load_from_local_raw_file(config, source)
                    .await?
            } else {
                self.remote_fetcher
                    .try_fetch_single_source(client, source, retry_policy)
                    .await?
            };

            rule_lib = Some(current_rule_lib);
            break;
        }

        let rule_lib =
            rule_lib.ok_or_else(|| RswappalyzerError::RuleLoadError("远程规则加载失败".into()))?;
        let cleaned = self.rule_processor.clean_and_split_rules(&rule_lib)?;

        self.rule_processor.save_to_cache(config, &cleaned).await;
        let _ = self
            .etag_manager
            .save_etag_records(config, &etag_total_record);

        Ok(cleaned)
    }

    #[cfg(feature = "remote-loader")]
    pub async fn fetch_remote(&self, config: &RuleConfig) -> RswResult<RuleLibrary> {
        self.fetch_remote_with_mode(config, crate::rule::loader::remote_source::FetchMode::Override)
            .await
    }

    #[cfg(feature = "remote-loader")]
    pub async fn fetch_remote_with_mode(
        &self,
        config: &RuleConfig,
        fetch_mode: crate::rule::loader::remote_source::FetchMode,
    ) -> RswResult<RuleLibrary> {
        let remote_opts = config
            .remote_options
            .as_ref()
            .ok_or_else(|| RswappalyzerError::RuleLoadError("远程规则缺少网络配置项".into()))?;
        let client = Client::builder().timeout(remote_opts.timeout).build()?;

        let remote_sources = self.remote_fetcher.build_remote_sources();
        let retry_policy = &remote_opts.retry;

        let mut rule_lib = match fetch_mode {
            crate::rule::loader::remote_source::FetchMode::Override => {
                self.remote_fetcher
                    .fetch_with_override(&client, &remote_sources, retry_policy)
                    .await?
            }
            crate::rule::loader::remote_source::FetchMode::Merge => {
                self.remote_fetcher
                    .fetch_with_merge(&client, &remote_sources, retry_policy)
                    .await?
            }
        };

        self.rule_processor.build_index(&mut rule_lib);
        Ok(rule_lib)
    }

    pub fn debug_count_script_rules(&self, rule_lib: &RuleLibrary) {
        self.rule_processor.debug_count_script_rules(rule_lib);
    }
}
