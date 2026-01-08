//! Remote rule fetcher module
//! 远程规则拉取工具
//! 核心特性：
//! 1. 纯异步设计（无block_on，基于tokio异步运行时）
//! 2. 可配置重试策略（Never/Times(n)）
//! 3. ETag缓存控制（支持弱ETag解析，W/前缀和引号处理）
//! 4. 特性条件编译（remote-loader特性控制功能开关）
//! 5. 鲁棒的错误处理（详细错误上下文，友好日志提示）

use crate::error::{RswResult, RswappalyzerError};
use crate::rule::loader::ETagRecord;
#[cfg(feature = "remote-loader")]
use reqwest::Client;
use rswappalyzer_engine::RuleLibrary;
use std::path::Path;

/// 远程规则拉取器
/// 设计：无状态工具类，专注于远程规则的拉取、ETag获取和重试逻辑
#[derive(Default)]
pub struct RemoteRuleFetcher;

impl RemoteRuleFetcher {
    /// 通用异步重试逻辑（纯异步，无阻塞）
    /// 特性：
    /// 1. 可配置最大重试次数
    /// 2. 指数退避（固定1秒间隔，可扩展）
    /// 3. 保留最后一次错误信息
    /// 4. 异步闭包支持（FnMut返回Future）
    /// 参数：
    /// - max_retries: 最大重试次数（0表示不重试）
    /// - func: 异步闭包，返回RswResult<T>
    /// 返回：执行结果 | 最后一次错误
    #[cfg(feature = "remote-loader")]
    #[cfg(feature = "remote-loader")]
    async fn simple_retry<F, Fut, T>(&self, max_retries: usize, mut func: F) -> RswResult<T>
    where
        // 泛型约束：func 返回一个 Send + 'static 的 Future
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = RswResult<T>> + Send + 'static,
    {
        let mut last_err: Option<RswappalyzerError> = None;

        for attempt in 0..=max_retries {
            match func().await {
                Ok(res) => return Ok(res),
                Err(e) => {
                    last_err = Some(e);
                    if attempt < max_retries {
                        log::warn!(
                            "Request failed, retrying (attempt {}/{})",
                            attempt + 1,
                            max_retries
                        );
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            RswappalyzerError::RuleLoadError("All retry attempts exhausted".to_string())
        }))
    }

    /// 获取远程资源的ETag（纯异步）
    /// 特性：
    /// 1. HEAD请求（轻量，仅获取Header）
    /// 2. 支持弱ETag解析（移除W/前缀和引号）
    /// 3. 重试策略适配（Never/Times(n)）
    /// 4. 友好错误处理（失败时返回Ok(None)，而非直接报错）
    /// 参数：
    /// - client: reqwest异步客户端
    /// - url: 远程资源URL
    /// - retry_policy: 重试策略
    /// 返回：ETag字符串（Option） | 错误（仅严重错误）
    #[cfg(feature = "remote-loader")]
    pub async fn get_remote_etag(
        &self,
        client: &Client,
        url: &str,
        retry_policy: &crate::RetryPolicy,
    ) -> RswResult<Option<String>> {
        // 解析重试次数
        let max_retries = match retry_policy {
            crate::RetryPolicy::Never => 0,
            crate::RetryPolicy::Times(n) => *n as usize,
        };

        let result = self
            .simple_retry(max_retries, || {
                // 捕获上下文变量（clone避免生命周期问题）
                let client = client.clone();
                let url = url.to_string();

                // 返回异步闭包
                Box::pin(async move {
                    // 发送HEAD请求获取ETag
                    let response = client
                        .head(&url)
                        .header("User-Agent", "Rswappalyzer/0.1.0")
                        .send()
                        .await
                        .map_err(|e| {
                            RswappalyzerError::RuleLoadError(format!(
                                "Failed to request ETag: {:#?}",
                                e
                            ))
                        })?;

                    // 检查响应状态码
                    if !response.status().is_success() {
                        return Err(RswappalyzerError::RuleLoadError(format!(
                            "Failed to get ETag: URL {} returned status code {}",
                            url,
                            response.status()
                        )));
                    }

                    // 提取并解析ETag
                    let etag = response
                        .headers()
                        .get(reqwest::header::ETAG)
                        .ok_or_else(|| {
                            RswappalyzerError::RuleLoadError(format!(
                                "URL {} did not return ETag header",
                                url
                            ))
                        })?
                        .to_str()
                        .map_err(|e| {
                            RswappalyzerError::RuleLoadError(format!(
                                "Failed to convert ETag to string: {}",
                                e
                            ))
                        })?;

                    // 清理ETag（移除W/前缀和引号）
                    let etag_clean = etag.trim_start_matches("W/").trim_matches('"').to_string();

                    Ok(etag_clean)
                })
            })
            .await;

        // 处理结果：成功返回Some(ETag)，失败返回None（记录警告）
        match result {
            Ok(etag) => {
                log::debug!("Successfully fetched ETag for URL [{}]: {}", url, etag);
                Ok(Some(etag))
            }
            Err(e) => {
                log::warn!("Failed to fetch ETag for URL [{}]: {}", url, e);
                Ok(None)
            }
        }
    }

    /// 拉取远程Wappalyzer规则库（纯异步）
    /// 特性：
    /// 1. GET请求（支持gzip/deflate压缩）
    /// 2. 自动解析原始规则为RuleLibrary
    /// 3. 重试策略适配
    /// 4. 详细的日志和错误上下文
    /// 参数：
    /// - client: reqwest异步客户端
    /// - url: 远程规则库URL
    /// - retry_policy: 重试策略
    /// 返回：解析后的RuleLibrary | 错误
    #[cfg(feature = "remote-loader")]
    pub async fn fetch_wappalyzer_rules(
        &self,
        client: &Client,
        url: &str,
        retry_policy: &crate::RetryPolicy,
    ) -> RswResult<RuleLibrary> {
        use rswappalyzer_engine::source::{
            wappalyzer::WappalyzerOriginalRuleLibrary, WappalyzerParser,
        };

        // 解析重试次数
        let max_retries = match retry_policy {
            crate::RetryPolicy::Never => 0,
            crate::RetryPolicy::Times(n) => *n as usize,
        };

        let rule_lib = self
            .simple_retry(max_retries, || {
                // 捕获上下文变量
                let client = client.clone();
                let url = url.to_string();

                // 返回异步闭包
                Box::pin(async move {
                    // 发送GET请求拉取规则
                    let response = client
                        .get(&url)
                        .header("User-Agent", "Rswappalyzer/0.1.0")
                        .header("Accept-Encoding", "gzip, deflate")
                        .send()
                        .await
                        .map_err(|e| {
                            RswappalyzerError::RuleLoadError(format!(
                                "Failed to fetch rules: {:#?}",
                                e
                            ))
                        })?;

                    // 检查响应状态码
                    if !response.status().is_success() {
                        return Err(RswappalyzerError::RuleLoadError(format!(
                            "Failed to fetch rules: URL {} returned status code {}",
                            url,
                            response.status()
                        )));
                    }

                    // 异步读取响应字节
                    let bytes = response.bytes().await.map_err(|e| {
                        RswappalyzerError::RuleLoadError(format!(
                            "Failed to read response bytes: {}",
                            e
                        ))
                    })?;

                    // 解析原始规则
                    let parser = WappalyzerParser::default();
                    let original_lib: WappalyzerOriginalRuleLibrary =
                        parser.parse_from_bytes(&bytes).map_err(|e| {
                            RswappalyzerError::RuleLoadError(format!(
                                "Failed to parse original rules: {}",
                                e
                            ))
                        })?;

                    // 转换为标准RuleLibrary
                    let rule_lib = parser.convert_original_to_rule_lib(original_lib);
                    Ok(rule_lib)
                })
            })
            .await?;

        // 记录成功日志
        log::debug!(
            "Successfully fetched Wappalyzer rules, total tech rules: {}",
            rule_lib.core_tech_map.len()
        );

        Ok(rule_lib)
    }

    /// 判断是否使用本地缓存文件
    /// 规则：
    /// 1. 本地ETag记录存在
    /// 2. ETag与远程一致
    /// 3. 本地文件存在
    /// 参数：
    /// - local_record: 本地ETag记录（Option）
    /// - remote_etag: 远程ETag
    /// 返回：是否使用本地文件（true/false）
    pub fn should_use_local_file(
        &self,
        local_record: &Option<ETagRecord>,
        remote_etag: &str,
    ) -> bool {
        local_record.as_ref().map_or(false, |r| {
            r.etag == remote_etag && Path::new(&r.local_file_path).exists()
        })
    }

    /// 未启用remote-loader特性时的占位实现（ETag获取）
    /// 返回：明确的特性未启用错误
    #[cfg(not(feature = "remote-loader"))]
    pub async fn get_remote_etag(
        &self,
        _client: &(), // 空元组占位（该分支不会被实际调用）
        _url: &str,
        _retry_policy: &crate::RetryPolicy,
    ) -> RswResult<Option<String>> {
        Err(RswappalyzerError::RuleLoadError(
            "remote-loader feature is not enabled".to_string(),
        ))
    }

    /// 未启用remote-loader特性时的占位实现（规则拉取）
    /// 返回：明确的特性未启用错误
    #[cfg(not(feature = "remote-loader"))]
    pub async fn fetch_wappalyzer_rules(
        &self,
        _client: &(), // 空元组占位（该分支不会被实际调用）
        _url: &str,
        _retry_policy: &crate::RetryPolicy,
    ) -> RswResult<RuleLibrary> {
        Err(RswappalyzerError::RuleLoadError(
            "remote-loader feature is not enabled".to_string(),
        ))
    }
}
