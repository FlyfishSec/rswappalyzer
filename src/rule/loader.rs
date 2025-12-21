//! 规则加载管理器
//! 负责从本地缓存或远程拉取规则库

use std::collections::HashMap;
use reqwest::Client;
use tracing::{debug, warn};
use serde::{Deserialize};
use serde_json::Value;

use super::model::{RuleLibrary, TechRule, CategoryRule};
use super::cache::RuleCacheManager;
use crate::error::{RswResult, RswappalyzerError};
use crate::config::GlobalConfig;
use crate::rule::source_eh::fetch_fallback_remote;
//use crate::rule::source_eh::fetch_fallback_remote;

/// 远程完整规则源配置（支持自定义顺序）
#[derive(Debug, Clone)]
pub struct RemoteRuleSource {
    /// 规则名称（用于日志输出）
    pub name: String,
    /// 原始URL
    pub raw_url: String,
    /// 规则类型（区分wappalyzergo的JSON和自定义MP格式）
    pub rule_type: RuleFileType,
}

/// 规则文件类型
#[derive(Debug, Clone, Copy)]
pub enum RuleFileType {
    /// wappalyzergo
    WappalyzerGoJson,
    /// wappalyzer_rules.mp
    Rswappalyzermp,
}

/// 规则加载管理器
pub struct RuleLoader;

impl RuleLoader {
    /// 加载规则库（优先本地缓存，缓存失效则拉取远程）
    pub async fn load(config: &GlobalConfig) -> RswResult<RuleLibrary> {
        // 1. 优先加载本地缓存
        if let Ok(rule_lib) = RuleCacheManager::load_from_cache(config).await {
            debug!("从本地缓存加载规则库成功");
            return Ok(rule_lib);
        }
        warn!("本地缓存不存在或损坏，将拉取远程规则库");

        // 2. 拉取远程规则库（优先完整规则文件）
        let rule_lib = Self::fetch_remote(config).await?;

        // 3. 缓存到本地
        if let Err(e) = RuleCacheManager::save_to_cache(config, &rule_lib).await {
            warn!("规则库缓存到本地失败：{}", e);
        } else {
            debug!("远程规则库已缓存到本地");
        }

        Ok(rule_lib)
    }

    // ===== 统计Script相关规则数量 =====
    fn debug_count_script_rules(rule_lib: &RuleLibrary) {
        let mut has_script_count = 0;
        let mut has_script_src_count = 0;
        let mut total_script_patterns = 0;
        let mut total_script_src_patterns = 0;

        for (tech_name, tech_rule) in &rule_lib.tech_rules {
            if let Some(script_val) = &tech_rule.scripts {
                has_script_count += 1;
                match script_val {
                    Value::String(_) => total_script_patterns += 1,
                    Value::Array(arr) => total_script_patterns += arr.len(),
                    _ => {}
                }
            }

            if let Some(script_src_val) = &tech_rule.script_src {
                has_script_src_count += 1;
                match script_src_val {
                    Value::String(_) => total_script_src_patterns += 1,
                    Value::Array(arr) => total_script_src_patterns += arr.len(),
                    _ => {}
                }
            }
        }

        debug!("===== 原始规则Script数据统计 =====");
        debug!("  技术规则总数：{}", rule_lib.tech_rules.len());
        debug!("  有scripts字段的规则数：{}", has_script_count);
        debug!("  有script_src字段的规则数：{}", has_script_src_count);
        debug!("  scripts字段正则总数（粗略）：{}", total_script_patterns);
        debug!("  script_src字段正则总数（粗略）：{}", total_script_src_patterns);
        debug!("  脚本相关正则总数（粗略）：{}", total_script_patterns + total_script_src_patterns);
    }

    /// 强制拉取远程规则库（优先完整规则文件，支持自定义顺序）
    pub async fn fetch_remote(config: &GlobalConfig) -> RswResult<RuleLibrary> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(config.http_timeout))
            .build()?;

        // debug!("开始尝试拉取原始构建源");

        // // ❶ 原始源：失败即终止
        // let rule_lib = fetch_fallback_remote(config).await.map_err(|e| {
        //     RswappalyzerError::RuleLoadError(format!(
        //         "原始构建源拉取失败，终止后续流程：{}",
        //         e
        //     ))
        // })?;
    
        // debug!(
        //     "原始构建源拉取成功，规则总数：{}",
        //     rule_lib.tech_rules.len()
        // );
        // return Ok(rule_lib);

        // ===== 自定义远程规则源顺序（可随意调整优先级）=====
        // 优先级：1. wappalyzergo 完整JSON > 2. 自定义MP文件
        let remote_sources = vec![
            RemoteRuleSource {
                name: "wappalyzergo".to_string(),
                raw_url: "https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/refs/heads/main/fingerprints_data.json".to_string(),
                rule_type: RuleFileType::WappalyzerGoJson,
            },
            RemoteRuleSource {
                name: "rswappalyzer".to_string(),
                raw_url: "https://raw.githubusercontent.com/FlyfishSec/rswappalyzer/refs/heads/master/wappalyzer_rules.mp".to_string(),
                rule_type: RuleFileType::Rswappalyzermp,
            },
        ];

        // 遍历自定义规则源，按顺序尝试拉取
        for source in remote_sources {
            debug!("开始尝试拉取 [{}]，URL：{}", source.name, source.raw_url);
            // 构建代理URL（如果原始URL失败）
            let proxy_path = source.raw_url.trim_start_matches("https://");
            let fallback_url = format!("{}{}", config.gh_proxy_url, proxy_path);

            // 先尝试原始URL，失败则尝试代理URL
            match Self::fetch_complete_rule_file(&client, &source.raw_url, source.rule_type).await {
                Ok(rule_lib) => {
                    debug!("成功拉取 [{}]，规则总数：{}", source.name, rule_lib.tech_rules.len());
                    return Ok(rule_lib);
                }
                Err(e) => {
                    warn!("拉取 [{}] 原始URL失败：{}，尝试代理URL：{}", source.name, e, fallback_url);
                    match Self::fetch_complete_rule_file(&client, &fallback_url, source.rule_type).await {
                        Ok(rule_lib) => {
                            debug!("通过代理成功拉取 [{}]，规则总数：{}", source.name, rule_lib.tech_rules.len());
                            return Ok(rule_lib);
                        }
                        Err(proxy_e) => {
                            warn!("拉取 [{}] 代理URL也失败：{}", source.name, proxy_e);
                            continue; // 尝试下一个规则源
                        }
                    }
                }
            }
        }

        // 所有完整规则源失败，尝试原始源构建
        // warn!("所有完整规则源拉取失败，尝试第三个数据源：后备分文件双数据源拉取");
        // match fetch_fallback_remote(config).await {
        //     Ok(rule_lib) => {
        //         debug!("后备分文件数据源拉取成功，规则总数：{}", rule_lib.tech_rules.len());
        //         return Ok(rule_lib);
        //     }
        //     Err(fallback_e) => {
        //         return Err(RswappalyzerError::RuleLoadError(format!(
        //             "所有数据源拉取失败：{}", fallback_e
        //         )));
        //     }
        // }    
        // 所有完整规则源都失败
        Err(RswappalyzerError::RuleLoadError("所有远程完整规则源拉取失败，请检查网络或URL配置".to_string()))
    }

    /// 拉取完整规则文件（支持不同格式）
    async fn fetch_complete_rule_file(client: &Client, url: &str, rule_type: RuleFileType) -> RswResult<RuleLibrary> {
        let response = client.get(url)
            .header("User-Agent", "Rswappalyzer/0.1.0")
            .header("Accept-Encoding", "gzip, deflate")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(RswappalyzerError::RuleLoadError(format!(
                "URL {} 返回状态码 {}",
                url, response.status()
            )));
        }

        // 根据规则类型解析数据
        match rule_type {
            RuleFileType::WappalyzerGoJson => {
                Self::parse_wappalyzer_go_json(response).await
            }
            RuleFileType::Rswappalyzermp => {
                Self::parse_rswappalyzer_msgpack(response).await
            }
        }
    }

    /// 解析wappalyzergo的fingerprints_data.json格式
    async fn parse_wappalyzer_go_json(response: reqwest::Response) -> RswResult<RuleLibrary> {
        // 定义wappalyzergo JSON对应的结构体
        #[derive(Debug, Deserialize)]
        struct WappalyzerGoFingerprint {
            #[serde(rename = "apps")]
            apps: HashMap<String, WappalyzerGoApp>,
        }
    
        #[derive(Debug, Deserialize)]
        struct WappalyzerGoApp {
            #[serde(rename = "cats")]
            cats: Vec<u32>,
            #[serde(rename = "headers")]
            headers: Option<HashMap<String, String>>,
            #[serde(rename = "meta")]
            meta: Option<HashMap<String, Vec<String>>>,
            #[serde(rename = "html")]
            html: Option<Vec<String>>,
            #[serde(rename = "scripts")]
            scripts: Option<Vec<String>>,
            #[serde(rename = "scriptSrc")]
            script_src: Option<Vec<String>>,
            #[serde(rename = "implies")]
            implies: Option<Vec<String>>,
            #[serde(rename = "description")]
            description: Option<String>,
            #[serde(rename = "website")]
            website: Option<String>,
            #[serde(rename = "icon")]
            icon: Option<String>,
            #[serde(rename = "cpe")]
            cpe: Option<String>,
        }
    
        // 解析JSON
        let wappalyzer_data: WappalyzerGoFingerprint = response.json().await?;
        let mut tech_rules = HashMap::new();
    
        // 转换为TechRule格式
        for (app_name, go_app) in wappalyzer_data.apps {
            // 将Vec<String>转换为serde_json::Value（保持不变）
            let scripts_val = go_app.scripts.map(|v| {
                if v.len() == 1 {
                    Value::String(v.into_iter().next().unwrap())
                } else {
                    Value::Array(v.into_iter().map(Value::String).collect())
                }
            });
    
            let script_src_val = go_app.script_src.map(|v| {
                if v.len() == 1 {
                    Value::String(v.into_iter().next().unwrap())
                } else {
                    Value::Array(v.into_iter().map(Value::String).collect())
                }
            });
    
            let html_val = go_app.html.map(|v| {
                if v.len() == 1 {
                    Value::String(v.into_iter().next().unwrap())
                } else {
                    Value::Array(v.into_iter().map(Value::String).collect())
                }
            });
    
            let meta_val = go_app.meta.map(|meta_map| {
                let mut meta_value = HashMap::new();
                for (k, v) in meta_map {
                    if v.len() == 1 {
                        meta_value.insert(k, Value::String(v.into_iter().next().unwrap()));
                    } else {
                        meta_value.insert(k, Value::Array(v.into_iter().map(Value::String).collect()));
                    }
                }
                meta_value
            });
    
            let headers_val = go_app.headers.map(|header_map| {
                let mut header_value = HashMap::new();
                for (k, v) in header_map {
                    header_value.insert(k, Value::String(v));
                }
                header_value
            });
    
            let tech_rule = TechRule {
                category_ids: go_app.cats,
                headers: headers_val,
                meta: meta_val,
                html: html_val,
                scripts: scripts_val,
                script_src: script_src_val,
                implies: go_app.implies.map(|v| {
                    if v.len() == 1 {
                        Value::String(v.into_iter().next().unwrap())
                    } else {
                        Value::Array(v.into_iter().map(Value::String).collect())
                    }
                }),
                description: go_app.description,
                website: go_app.website,
                icon: go_app.icon,
                cpe: go_app.cpe,
                saas: None,
                pricing: None,
                url: None,
            };
    
            tech_rules.insert(app_name, tech_rule);
        }
    
        // 构建分类规则
        let category_rules = Self::get_default_categories();
    
        Ok(RuleLibrary {
            tech_rules,
            category_rules,
        })
    }

    /// 解析msgpack格式规则
    async fn parse_rswappalyzer_msgpack(
        response: reqwest::Response,
    ) -> RswResult<RuleLibrary> {
        let bytes = response.bytes().await.map_err(|e| {
            RswappalyzerError::RuleLoadError(format!(
                "读取 mp 响应体失败：{}",
                e
            ))
        })?;
    
        let rule_lib: RuleLibrary = rmp_serde::from_slice(&bytes).map_err(|e| {
            RswappalyzerError::RuleLoadError(format!(
                "反序列化 mp 失败：{}",
                e
            ))
        })?;
    
        Ok(rule_lib)
    }
    

    /// 获取默认分类
    fn get_default_categories() -> HashMap<String, CategoryRule> {
        let mut categories = HashMap::new();
        let default_cats = vec![
            (1, "CMS"), (2, "Message Boards"), (3, "Database Managers"), (4, "Documentation"),
            (5, "Widgets"), (6, "Ecommerce"), (7, "Photo Galleries"), (8, "Wikis"),
            (9, "Hosting Panels"), (10, "Analytics"), (11, "Blogs"), (12, "JavaScript Frameworks"),
            (13, "Issue Trackers"), (14, "Video Players"), (15, "Comment Systems"), (16, "Security"),
            (17, "Font Scripts"), (18, "Web Frameworks"), (19, "Miscellaneous"), (20, "Editors"),
        ];

        for (id, name) in default_cats {
            categories.insert(id.to_string(), CategoryRule {
                name: name.to_string(),
                priority: Some(id),
                id,
            });
        }

        categories
    }
}