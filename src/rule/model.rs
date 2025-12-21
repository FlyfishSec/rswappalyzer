//! 规则数据模型定义
//! 仅存储规则数据，无任何业务逻辑，支持序列化/反序列化

use std::collections::HashMap;
use std::fmt;
use serde::{Deserialize, Serialize};

/// 技术检测结果（完整版本）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technology {
    pub name: String,
    pub confidence: u8,
    pub version: Option<String>,
    pub categories: Vec<String>,
    pub website: Option<String>,
    pub description: Option<String>,
    pub icon: Option<String>,
    pub cpe: Option<String>,
    pub saas: Option<bool>,
    pub pricing: Option<Vec<String>>,
}

impl Technology {
    /// 从名称快速创建（默认值）
    pub fn from_name(name: String) -> Self {
        Self {
            name,
            confidence: 50,
            version: None,
            categories: Vec::new(),
            website: None,
            description: None,
            icon: None,
            cpe: None,
            saas: None,
            pricing: None,
        }
    }
}

// ======== 为 Technology 实现 Display trait（用于 CLI / Report 输出） ========
impl fmt::Display for Technology {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.version {
            Some(v) if !v.is_empty() => write!(f, "{} {}", self.name, v),
            _ => write!(f, "{}", self.name),
        }
    }
}

/// 技术检测结果（精简版本）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechnologyLite {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "is_default_confidence")]
    pub confidence: u8,
}

impl TechnologyLite {
    /// 从名称快速创建 TechnologyLite（默认值，与 Technology::from_name 行为一致）
    pub fn from_name(name: String) -> Self {
        Self {
            name,
            version: None, // 未知版本用 None
            confidence: 50, // 降级识别默认置信度（与完整版本保持一致）
        }
    }
}

// ======== 为 TechnologyLite 实现 Display trait（用于 CLI / Report 输出） ========
impl fmt::Display for TechnologyLite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.version {
            Some(v) if !v.is_empty() => write!(f, "{} {}", self.name, v),
            _ => write!(f, "{}", self.name),
        }
    }
}

// ======== 类型转换 ========
impl From<Technology> for TechnologyLite {
    fn from(full: Technology) -> Self {
        Self {
            name: full.name,
            version: full.version,
            confidence: full.confidence,
        }
    }
}

// ======== 辅助函数：置信度100时不序列化 ========
fn is_default_confidence(conf: &u8) -> bool {
    *conf == 100
}

/// 技术规则定义（从 Wappalyzer JSON 解析）
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TechRule {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub website: Option<String>,
    #[serde(rename = "cats", default, alias = "categories")]
    pub category_ids: Vec<u32>,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub cpe: Option<String>,
    #[serde(default)]
    pub saas: Option<bool>,
    #[serde(default)]
    pub pricing: Option<Vec<String>>,

    // 检测规则
    #[serde(default)]
    pub url: Option<serde_json::Value>,
    #[serde(default)]
    pub html: Option<serde_json::Value>,
    #[serde(default)]
    pub scripts: Option<serde_json::Value>,
    // 兼容：wappalyzergo 的 scriptSrc 字段
    #[serde(rename = "scriptSrc", default)]
    pub script_src: Option<serde_json::Value>,
    #[serde(default)]
    pub meta: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub headers: Option<HashMap<String, serde_json::Value>>,

    // 关联规则
    #[serde(default)]
    pub implies: Option<serde_json::Value>,
}

/// 分类规则定义（从 Wappalyzer JSON 解析）
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CategoryRule {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub priority: Option<u32>,
    #[serde(default)]
    pub id: u32,
}

/// 完整规则库
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleLibrary {
    pub tech_rules: HashMap<String, TechRule>,
    pub category_rules: HashMap<String, CategoryRule>,
}
