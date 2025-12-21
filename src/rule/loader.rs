//! 规则加载管理器
//! 负责从本地缓存或远程拉取规则库

use std::collections::HashMap;
use reqwest::Client;
use tracing::{debug, warn};

use super::model::{RuleLibrary, TechRule, CategoryRule};
use super::cache::RuleCacheManager;
use crate::error::{RswResult, RswappalyzerError};
use crate::config::GlobalConfig;

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

        // 2. 拉取远程规则库
        let rule_lib = Self::fetch_remote(config).await?;

        // 3. 缓存到本地
        if let Err(e) = RuleCacheManager::save_to_cache(config, &rule_lib).await {
            warn!("规则库缓存到本地失败：{}", e);
        } else {
            debug!("远程规则库已缓存到本地");
        }

        Ok(rule_lib)
    }

    /// 强制拉取远程规则库（忽略本地缓存）
    pub async fn fetch_remote(config: &GlobalConfig) -> RswResult<RuleLibrary> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(config.http_timeout))
            .build()?;
    
        // 1. 拉取技术规则（a-z + _）
        let tech_letters = ('a'..='z').chain(std::iter::once('_'));
        let mut tech_rules = HashMap::new();
    
        for letter in tech_letters {
            let original_url = format!(
                "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/{}.json",
                letter
            );
            let fallback_url = format!(
                "{}raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/{}.json",
                config.gh_proxy_url, letter
            );
    
            // 尝试原始 URL，失败再用代理
            let letter_tech_rules = match Self::fetch_tech_file(&client, &original_url).await {
                Ok(rules) => rules,
                Err(_) => {
                    debug!("原始仓库拉取 {} 规则失败，尝试代理 URL", letter);
                    Self::fetch_tech_file(&client, &fallback_url).await?
                }
            };
    
            tech_rules.extend(letter_tech_rules);
        }
    
        if tech_rules.is_empty() {
            return Err(RswappalyzerError::RuleLoadError("未拉取到任何技术规则".to_string()));
        }
    
        // 2. 拉取分类规则
        let original_cat_url =
            "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/categories.json";
        let fallback_cat_url = &format!("{}raw.githubusercontent.com/enthec/webappanalyzer/main/src/categories.json", config.gh_proxy_url);
    
        let category_rules = match Self::fetch_category_file(&client, original_cat_url).await {
            Ok(rules) => rules,
            Err(_) => {
                debug!("原始仓库拉取分类规则失败，尝试代理 URL");
                match Self::fetch_category_file(&client, fallback_cat_url).await {
                    Ok(rules) => rules,
                    Err(_) => {
                        debug!("代理仓库拉取分类规则失败，使用默认分类");
                        Self::get_default_categories()
                    }
                }
            }
        };
    
        Ok(RuleLibrary {
            tech_rules,
            category_rules,
        })
    }
    
    pub async fn fetch_remote_old(config: &GlobalConfig) -> RswResult<RuleLibrary> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(config.http_timeout))
            .build()?;

        // 1. 拉取技术规则（a-z + _）
        let tech_letters = vec!['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '_'];
        let mut tech_rules = HashMap::new();

        for letter in tech_letters {
            let main_url = Self::build_remote_url(config, &format!(
                "raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/{}.json",
                letter
            ));
            let fallback_url = Self::build_remote_url(config, &format!(
                "raw.githubusercontent.com/HTTPArchive/wappalyzer/main/src/technologies/{}.json",
                letter
            ));

            // 拉取单个技术规则文件
            let letter_tech_rules = match Self::fetch_tech_file(&client, &main_url).await {
                Ok(rules) => rules,
                Err(_) => {
                    debug!("主仓库拉取{}规则失败，尝试备用仓库", letter);
                    Self::fetch_tech_file(&client, &fallback_url).await?
                }
            };

            tech_rules.extend(letter_tech_rules);
        }

        if tech_rules.is_empty() {
            return Err(RswappalyzerError::RuleLoadError("未拉取到任何技术规则".to_string()));
        }

        // 2. 拉取分类规则
        let main_cat_url = Self::build_remote_url(config, "raw.githubusercontent.com/enthec/webappanalyzer/main/src/categories.json");
        let fallback_cat_url = Self::build_remote_url(config, "raw.githubusercontent.com/HTTPArchive/wappalyzer/main/src/categories.json");
        let category_rules = match Self::fetch_category_file(&client, &main_cat_url).await {
            Ok(rules) => rules,
            Err(_) => {
                debug!("主仓库拉取分类规则失败，尝试备用仓库");
                match Self::fetch_category_file(&client, &fallback_cat_url).await {
                    Ok(rules) => rules,
                    Err(_) => {
                        debug!("备用仓库拉取分类规则失败，使用默认分类");
                        Self::get_default_categories()
                    }
                }
            }
        };

        Ok(RuleLibrary {
            tech_rules,
            category_rules,
        })
    }

    /// 构建带代理的远程URL
    fn build_remote_url(config: &GlobalConfig, path: &str) -> String {
        format!("{}{}", config.gh_proxy_url, path)
    }

    /// 拉取单个技术规则文件
    async fn fetch_tech_file(client: &Client, url: &str) -> RswResult<HashMap<String, TechRule>> {
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

        let tech_rules = response.json().await?;
        Ok(tech_rules)
    }

    /// 拉取分类规则文件
    async fn fetch_category_file(client: &Client, url: &str) -> RswResult<HashMap<String, CategoryRule>> {
        let response = client.get(url)
            .header("User-Agent", "Rswappalyzer/0.1.0")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(RswappalyzerError::RuleLoadError(format!(
                "URL {} 返回状态码 {}",
                url, response.status()
            )));
        }

        let mut categories = response
            .json::<HashMap<String, CategoryRule>>()
            .await?;
        // 补充分类ID
        for (key, cat) in &mut categories {
            if let Ok(id) = key.parse::<u32>() {
                cat.id = id;
            }
        }

        Ok(categories)
    }

    /// 获取默认分类（远程拉取失败时使用）
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