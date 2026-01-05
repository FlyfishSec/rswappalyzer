//! Wappalyzer 专属规则模型
//! 仅存放 Wappalyzer 规则的原始结构

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Wappalyzer 原始分类规则
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WappalyzerOriginalCategory {
    pub name: String,
    pub priority: Option<u32>,
}

/// Wappalyzer 原始技术规则
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WappalyzerOriginalTechRule {
    #[serde(rename = "cats", default)]
    pub category_ids: Vec<u32>,
    // 关联规则
    #[serde(default)]
    pub implies: Option<serde_json::Value>,

    #[cfg(feature = "full-meta")]
    #[serde(default)]
    pub description: Option<String>,
    #[cfg(feature = "full-meta")]
    #[serde(default)]
    pub website: Option<String>,
    #[cfg(feature = "full-meta")]
    #[serde(default)]
    pub icon: Option<String>,
    #[cfg(feature = "full-meta")]
    #[serde(default)]
    pub cpe: Option<String>,
    #[cfg(feature = "full-meta")]
    #[serde(default)]
    pub saas: Option<bool>,
    #[cfg(feature = "full-meta")]
    #[serde(default)]
    pub pricing: Option<Vec<String>>,

    // 检测规则（原始）
    #[serde(default)]
    pub url: Option<serde_json::Value>,
    #[serde(default)]
    pub html: Option<serde_json::Value>,
    #[serde(default)]
    pub scripts: Option<serde_json::Value>,
    #[serde(rename = "scriptSrc", default)]
    pub script_src: Option<serde_json::Value>,
    #[serde(default)]
    pub meta: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub headers: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub cookies: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub js: Option<HashMap<String, serde_json::Value>>,

    #[cfg(feature = "full-meta")]
    #[serde(flatten)]
    pub extra_fields: HashMap<String, serde_json::Value>,
}

/// Wappalyzer 原始规则库
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WappalyzerOriginalRuleLibrary {
    #[serde(rename = "technologies", alias = "apps")]
    pub technologies: HashMap<String, WappalyzerOriginalTechRule>,
    #[serde(default)]
    pub categories: HashMap<u32, WappalyzerOriginalCategory>,
}
