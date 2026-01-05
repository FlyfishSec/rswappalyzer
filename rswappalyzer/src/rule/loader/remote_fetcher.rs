
use std::fs;
use std::path::{Path, PathBuf};
use log::{debug};
use crate::{RuleConfig};
use crate::error::{RswResult, RswappalyzerError};
use crate::rule::loader::ETagRecord;
use crate::rule::loader::path_manager::RulePathManager;
use crate::rule::loader::remote_source::{RemoteRuleSource};
use crate::rule::core::{RuleLibrary};
use crate::rule::source::wappalyzer_go::original::WappalyzerOriginalRuleLibrary;
use crate::rule::transformer::{RuleTransformer, WappalyzerGoTransformer};
use crate::{WappalyzerGoParser};
use crate::rule::source::RuleFileType;

/// 远程规则拉取器（专门处理远程规则的获取与本地原始文件保存）
#[derive(Default)]
pub struct RemoteRuleFetcher {
    path_manager: RulePathManager,
}

impl RemoteRuleFetcher {
    // 通用重试执行器
    #[cfg(feature = "remote-loader")]
    async fn with_retry<F, T>(&self, retry_policy: &crate::RetryPolicy, mut func: F) -> RswResult<T>
    where
        F: FnMut() -> tokio::task::JoinHandle<RswResult<T>>,
    {
        let max_retries = match retry_policy {
            RetryPolicy::Never => 0,
            RetryPolicy::Times(n) => *n as usize,
        };

        let mut last_err: Option<RswappalyzerError> = None;
        // 执行：1次主请求 + N次重试
        for attempt in 0..=max_retries {
            match func().await? {
                Ok(res) => {
                    if attempt > 0 {
                        info!("请求重试成功，第{}次重试", attempt);
                    }
                    return Ok(res);
                }
                Err(e) => {
                    last_err = Some(e);
                    if attempt >= max_retries {
                        break;
                    }
                    log::warn!("⚠️ 请求失败，准备第{}次重试，错误：{}", attempt + 1, last_err.as_ref().unwrap());
                    // 指数退避：每次重试间隔 1s * 2^attempt，避免高频重试
                    tokio::time::sleep(std::time::Duration::from_secs(1 << attempt)).await;
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            RswappalyzerError::RuleLoadError("请求重试耗尽，无错误信息".to_string())
        }))
    }

    /// 获取远程资源的 ETag
    #[cfg(feature = "remote-loader")]
    pub async fn get_remote_etag(&self, client: &reqwest::Client, url: &str, retry_policy: &RetryPolicy) -> RswResult<Option<String>> {
        let url_clone = url.to_string();
        let result = self.with_retry(retry_policy, || {
            let client_inner = client.clone();
            let url_inner = url_clone.clone();
            tokio::spawn(async move {
                let response = client_inner.head(&url_inner)
                    .header("User-Agent", "Rswappalyzer/0.1.0")
                    .send()
                    .await?;

                if !response.status().is_success() {
                    return Err(RswappalyzerError::RuleLoadError(format!(
                        "URL {} 返回状态码 {}",
                        url_inner, response.status()
                    )));
                }

                let etag = response.headers()
                    .get(reqwest::header::ETAG)
                    .ok_or_else(|| RswappalyzerError::RuleLoadError(format!("URL {} 未返回 ETag 头", url_inner)))?
                    .to_str()?
                    .trim_start_matches("W/")
                    .trim_matches('"')
                    .to_string();

                Ok(etag)
            })
        }).await;

        match result {
            Ok(etag) => Ok(Some(etag)),
            Err(e) => {
                log::warn!("获取 URL [{}] ETag 失败：{}", url, e);
                Ok(None)
            }
        }
    }

    /// 判断是否使用本地文件 - 无修改
    pub fn should_use_local_file(&self, local_record: &Option<ETagRecord>, remote_etag: &str) -> bool {
        if let Some(local_record) = local_record {
            let is_etag_match = local_record.etag == remote_etag;
            let local_file_exists = Path::new(&local_record.local_file_path).exists();
            is_etag_match && local_file_exists
        } else {
            false
        }
    }

    /// 从本地原始文件加载规则 ✅ 修复 GlobalConfig → RuleConfig
    pub async fn load_from_local_raw_file(
        &self,
        config: &RuleConfig,
        source: &RemoteRuleSource,
    ) -> RswResult<RuleLibrary> {
        let local_path = self.path_manager.generate_local_raw_file_path(config, source);
        if !local_path.exists() {
            return Err(RswappalyzerError::RuleLoadError(format!(
                "本地原始文件不存在：{}",
                local_path.display()
            )));
        }
    
        debug!("从本地原始文件加载 [{}]：{}", source.name, local_path.display());
        let bytes = fs::read(&local_path)?;
    
        // 1. 解析原始规则（不再直接转为 RuleLibrary）
        let any_result = source.parser.parse_from_bytes(&bytes)?;
        
        // 2. 根据源类型转换为标准 RuleLibrary（核心修复）
        let rule_lib = match source.rule_file_type {
            RuleFileType::WappalyzerGoJson => {
                let original_lib: Box<WappalyzerOriginalRuleLibrary> = any_result
                    .downcast::<WappalyzerOriginalRuleLibrary>()
                    .map_err(|_| RswappalyzerError::RuleLoadError(
                        "解析器返回类型不匹配，无法转换为 WappalyzerOriginalRuleLibrary".to_string()
                    ))?;
                
                let transformer = WappalyzerGoTransformer::new(*original_lib);
                transformer.transform()?
            }
            RuleFileType::FingerprintHubJson => {
                Err(RswappalyzerError::RuleLoadError(
                    "FingerprintHub 转换器暂未实现".to_string()
                ))?
            }
            // RuleFileType::RswappalyzerMsgpack => {
            //     let cached_lib: Box<RuleLibrary> = any_result
            //         .downcast::<RuleLibrary>()
            //         .map_err(|_| RswappalyzerError::RuleLoadError(
            //             "解析器返回类型不匹配，无法转换为 RuleLibrary".to_string()
            //         ))?;
            //     *cached_lib
            // }
        };
    
        Ok(rule_lib)
    }
    
    /// 保存远程原始文件到本地 ✅ 修复 GlobalConfig → RuleConfig
    pub fn save_remote_raw_file(&self, config: &RuleConfig, source: &RemoteRuleSource, bytes: &[u8]) -> RswResult<PathBuf> {
        let local_path = self.path_manager.generate_local_raw_file_path(config, source);
        if let Some(parent) = local_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        fs::write(&local_path, bytes)?;
        debug!("远程原始文件已保存到本地：{}", local_path.display());
        Ok(local_path)
    }

    /// 尝试拉取单个远程规则源
    #[cfg(feature = "remote-loader")]
    pub async fn try_fetch_single_source(
        &self,
        client: &Client,
        source: &RemoteRuleSource,
        retry_policy: &RetryPolicy,
    ) -> RswResult<RuleLibrary> {
        debug!("开始尝试拉取 [{}]，URL：{}", source.name, source.raw_url);
        // 直接拉取原始URL，无代理fallback
        let rule_lib = self.fetch_complete_rule_file(client, &source.raw_url, source, retry_policy).await?;
        debug!("成功拉取 [{}]，规则总数：{}", source.name, rule_lib.core_tech_map.len());
        Ok(rule_lib)
    }

    /// 拉取完整规则文件并解析
    #[cfg(feature = "remote-loader")]
    async fn fetch_complete_rule_file(
        &self,
        client: &Client,
        url: &str,
        source: &RemoteRuleSource,
        retry_policy: &RetryPolicy,
    ) -> RswResult<RuleLibrary> {
        let url_clone = url.to_string();

        self.with_retry(retry_policy, || {
            let client_inner = client.clone();
            let url_inner = url_clone.clone();
            let source_inner = source.clone();
            tokio::spawn(async move {
                let response = client_inner.get(&url_inner)
                    .header("User-Agent", "Rswappalyzer/0.1.0")
                    .header("Accept-Encoding", "gzip, deflate")
                    .send()
                    .await?;
        
                if !response.status().is_success() {
                    return Err(RswappalyzerError::RuleLoadError(format!(
                        "URL {} 返回状态码 {}",
                        url_inner, response.status()
                    )));
                }
        
                // if source_inner.rule_file_type == RuleFileType::RswappalyzerMsgpack {
                //     return Self::parse_rswappalyzer_msgpack_static(response).await;
                // }
        
                let any_result = source_inner.parser.parse_from_response(response).await?;
                let rule_lib = match source_inner.rule_file_type {
                    RuleFileType::WappalyzerGoJson => {
                        let original_lib: Box<WappalyzerOriginalRuleLibrary> = any_result
                            .downcast::<WappalyzerOriginalRuleLibrary>()
                            .map_err(|_| RswappalyzerError::RuleLoadError(
                                "解析器返回类型不匹配，无法转换为 WappalyzerOriginalRuleLibrary".to_string()
                            ))?;
                        let transformer = WappalyzerGoTransformer::new(*original_lib);
                        transformer.transform()?
                    }
                    RuleFileType::FingerprintHubJson => {
                        Err(RswappalyzerError::RuleLoadError(
                            "FingerprintHub 转换器暂未实现".to_string()
                        ))?
                    }
                };
        
                Ok(rule_lib)
            })
        }).await
    }

    // 静态方法封装msgpack解析，解决异步闭包的生命周期问题
    // async fn parse_rswappalyzer_msgpack_static(response: reqwest::Response) -> RswResult<RuleLibrary> {
    //     let bytes = response.bytes().await.map_err(|e| {
    //         RswappalyzerError::RuleLoadError(format!("读取 mp 响应体失败：{}", e))
    //     })?;

    //     let cached_rules: Vec<CachedTechRule> = from_slice(&bytes).map_err(|e| {
    //         RswappalyzerError::RuleLoadError(format!("反序列化 mp 失败：{}", e))
    //     })?;

    //     let mut core_tech_map = HashMap::new();
    //     let mut category_rules = HashMap::new();

    //     for cached in cached_rules {
    //         let mut match_rules: HashMap<MatchScope, MatchRuleSet> = HashMap::new();
    //         for (scope, cached_scope_rule) in cached.rules {
    //             let rule_set = MatchRuleSet::from_cached(&scope, cached_scope_rule);
    //             match_rules.insert(scope, rule_set);
    //         }

    //         let parsed = ParsedTechRule {
    //             basic: cached.basic,
    //             match_rules,
    //         };

    //         core_tech_map.insert(
    //             parsed.basic.tech_name.clone().expect("TechBasicInfo.tech_name 不能为空"),
    //             parsed,
    //         );
    //     }

    //     Ok(RuleLibrary {
    //         core_tech_map,
    //         category_rules,
    //     })
    // }
    
    /// 构建远程规则源列表 - 无修改
    pub fn build_remote_sources(&self) -> Vec<RemoteRuleSource> {
        vec![
            RemoteRuleSource::new(
                "wappalyzergo",
                "https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/refs/heads/main/fingerprints_data.json",
                WappalyzerGoParser::default()
            ),
        ]
    }

    /// 多源合并模式拉取
    #[cfg(feature = "remote-loader")]
    pub async fn fetch_with_merge(
        &self,
        client: &Client,
        remote_sources: &[RemoteRuleSource],
        retry_policy: &RetryPolicy,
    ) -> RswResult<RuleLibrary> {
        let mut merged_core_tech_map: HashMap<String, ParsedTechRule> = HashMap::new();
        let mut merged_category_rules = HashMap::new();

        for source in remote_sources {
            match self.try_fetch_single_source(client, source, retry_policy).await {
                Ok(rule_lib) => {
                    let prev_count = merged_core_tech_map.len();
                    merged_core_tech_map.extend(rule_lib.core_tech_map);
                    merged_category_rules.extend(rule_lib.category_rules);
                    let added_count = merged_core_tech_map.len() - prev_count;
                    debug!(
                        "成功合并 [{}] 规则：新增 {} 条技术规则，当前总技术规则数：{}",
                        source.name, added_count, merged_core_tech_map.len()
                    );
                }
                Err(e) => {
                    warn!("跳过无效规则源 [{}]：{}", source.name, e);
                    continue;
                }
            }
        }

        if merged_core_tech_map.is_empty() {
            return Err(RswappalyzerError::RuleLoadError(
                "所有远程规则源（合并模式）拉取失败或无有效规则".to_string()
            ));
        }

        Ok(RuleLibrary {
            core_tech_map: merged_core_tech_map,
            category_rules: merged_category_rules,
        })
    }

    /// 优先级覆盖模式拉取
    #[cfg(feature = "remote-loader")]
    pub async fn fetch_with_override(
        &self,
        client: &Client,
        remote_sources: &[RemoteRuleSource],
        retry_policy: &RetryPolicy,
    ) -> RswResult<RuleLibrary> {
        for source in remote_sources {
            match self.try_fetch_single_source(client, source, retry_policy).await {
                Ok(rule_lib) => {
                    return Ok(rule_lib);
                }
                Err(e) => {
                    warn!("跳过无效规则源 [{}]：{}", source.name, e);
                    continue;
                }
            }
        }

        Err(RswappalyzerError::RuleLoadError(
            "所有远程规则源（覆盖模式）拉取失败，请检查网络或URL配置".to_string()
        ))
    }

    pub fn build_remote_sources_from_url(&self, base_url: &str) -> Vec<RemoteRuleSource> {
        vec![
            RemoteRuleSource::new(
                "custom_remote",
                base_url,
                WappalyzerGoParser::default()
            )
        ]
    }
}