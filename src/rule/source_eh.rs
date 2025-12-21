//! 规则拉取后备数据源（分文件拉取：enthec + HTTPArchive）
//! 作为第三个数据源，仅在完整规则文件拉取失败时使用

use std::collections::HashMap;
use reqwest::Client;
use tracing::{debug, warn};

use crate::rule::model::{RuleLibrary, TechRule, CategoryRule};
use super::super::error::{RswResult, RswappalyzerError};
use super::super::config::GlobalConfig;

#[derive(Debug, Clone, Copy)]
pub enum RawUrlStatus {
    // 未尝试（初始状态）
    Untried,
    // 可访问（后续优先用原始URL）
    Accessible,
    // 不可访问（后续直接用代理URL）
    Inaccessible,
}

/// 后备数据源拉取：分文件拉取双数据源规则
pub async fn fetch_fallback_remote(config: &GlobalConfig) -> RswResult<RuleLibrary> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(config.http_timeout))
        .build()?;

    // 定义双数据源：enthec（核心） + HTTPArchive（补充）
    let data_sources = [
        // 数据源1：enthec 官方核心仓库
        "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/{}.json",
        // 数据源2：HTTPArchive 补充仓库（后拉取，覆盖同名规则）
        "https://raw.githubusercontent.com/HTTPArchive/wappalyzer/main/src/technologies/{}.json",
    ];

    // 1. 拉取技术规则（a-z + _）
    let tech_letters = ('a'..='z').chain(std::iter::once('_'));
    let mut tech_rules = HashMap::new();
    // 初始化原始URL状态为「未尝试」
    let mut raw_url_status = RawUrlStatus::Untried;

    for letter in tech_letters {
        debug!("开始拉取字母 [{}] 的双数据源规则", letter);
        let mut letter_tech_rules = HashMap::new();

        // 遍历双数据源，后拉取的数据源覆盖先拉取的
        for (source_idx, source_template) in data_sources.iter().enumerate() {
            let source_name = if source_idx == 0 { "enthec（核心仓库）" } else { "HTTPArchive（补充仓库）" };
            let original_url = source_template.replace("{}", &letter.to_string());
            let proxy_path = original_url.trim_start_matches("https://");
            let fallback_url = format!("{}{}", config.gh_proxy_url, proxy_path);

            // 根据全局状态决定请求策略
            let current_tech_rules = match raw_url_status {
                RawUrlStatus::Untried => {
                    // 第一次尝试：先试原始URL，失败则标记为不可访问，后续用代理
                    match fetch_tech_file(&client, &original_url).await {
                        Ok(rules) => {
                            debug!("[{}][{}] 原始URL拉取成功", letter, source_name);
                            raw_url_status = RawUrlStatus::Accessible;
                            rules
                        }
                        Err(_) => {
                            debug!("[{}][{}] 原始URL拉取失败，尝试代理URL", letter, source_name);
                            raw_url_status = RawUrlStatus::Inaccessible;
                            fetch_tech_file(&client, &fallback_url).await?
                        }
                    }
                }
                RawUrlStatus::Accessible => {
                    // 原始URL可访问：优先尝试原始URL，失败则切换为代理
                    match fetch_tech_file(&client, &original_url).await {
                        Ok(rules) => {
                            debug!("[{}][{}] 原始URL拉取成功", letter, source_name);
                            rules
                        }
                        Err(_) => {
                            warn!("[{}][{}] 原始URL拉取失败，切换为代理URL", letter, source_name);
                            raw_url_status = RawUrlStatus::Inaccessible;
                            fetch_tech_file(&client, &fallback_url).await?
                        }
                    }
                }
                RawUrlStatus::Inaccessible => {
                    // 原始URL不可访问：直接使用代理URL，不再尝试原始URL
                    debug!("[{}][{}] 原始URL不可访问，直接使用代理URL拉取", letter, source_name);
                    fetch_tech_file(&client, &fallback_url).await?
                }
            };

            // 覆盖式合并：当前数据源规则覆盖已有规则（后数据源覆盖前数据源）
            let prev_count = letter_tech_rules.len();
            letter_tech_rules.extend(current_tech_rules);
            let curr_count = letter_tech_rules.len();
            debug!("[{}][{}] 合并完成，新增/覆盖规则数：{}", letter, source_name, curr_count - prev_count);
        }

        // 将当前字母的合并规则加入全局规则
        tech_rules.extend(letter_tech_rules);
        debug!("字母 [{}] 双数据源规则拉取完成，累计全局规则数：{}", letter, tech_rules.len());
    }

    if tech_rules.is_empty() {
        return Err(RswappalyzerError::RuleLoadError("未拉取到任何技术规则".to_string()));
    }
    debug!("双数据源技术规则拉取完成，最终规则总数：{}", tech_rules.len());

    // 2. 拉取分类规则（仅使用enthec仓库，保持分类一致性）
    let original_cat_url = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/categories.json";
    let proxy_cat_path = original_cat_url.trim_start_matches("https://");
    let fallback_cat_url = format!("{}{}", config.gh_proxy_url, proxy_cat_path);

    let category_rules = match raw_url_status {
        RawUrlStatus::Untried | RawUrlStatus::Accessible => {
            // 原始URL可访问/未尝试：先试原始URL
            match fetch_category_file(&client, original_cat_url).await {
                Ok(rules) => {
                    debug!("分类规则（enthec仓库）原始URL拉取成功");
                    rules
                }
                Err(_) => {
                    debug!("分类规则（enthec仓库）原始URL拉取失败，尝试代理URL");
                    match fetch_category_file(&client, &fallback_cat_url).await {
                        Ok(rules) => {
                            debug!("分类规则（enthec仓库）代理URL拉取成功");
                            rules
                        }
                        Err(_) => {
                            debug!("分类规则（enthec仓库）代理URL拉取失败，使用默认分类");
                            get_default_categories()
                        }
                    }
                }
            }
        }
        RawUrlStatus::Inaccessible => {
            // 原始URL不可访问：直接试代理URL
            debug!("原始URL不可访问，直接使用代理URL拉取分类规则（enthec仓库）");
            match fetch_category_file(&client, &fallback_cat_url).await {
                Ok(rules) => {
                    debug!("分类规则（enthec仓库）代理URL拉取成功");
                    rules
                }
                Err(_) => {
                    debug!("分类规则（enthec仓库）代理URL拉取失败，使用默认分类");
                    get_default_categories()
                }
            }
        }
    };

    Ok(RuleLibrary {
        tech_rules,
        category_rules,
    })
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