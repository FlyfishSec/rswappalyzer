use serde::{Deserialize, Serialize};

/// 分类规则定义（通用，多源解析后统一结构）
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct CategoryRule {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub priority: Option<u32>,
    #[serde(default)]
    pub id: u32,
}

/// 技术基础信息，仅存储描述/分类等元信息，无匹配规则
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct TechBasicInfo {
    pub tech_name: Option<String>,
    pub category_ids: Vec<u32>,
    #[serde(default)]
    pub implies: Option<Vec<String>>,

    // 非规则必须字段 - 特性开关控制
    #[cfg(feature = "full-meta")]
    pub cpe: Option<String>,
    #[cfg(feature = "full-meta")]
    pub description: Option<String>,
    #[cfg(feature = "full-meta")]
    pub website: Option<String>,
    #[cfg(feature = "full-meta")]
    pub icon: Option<String>,
    #[cfg(feature = "full-meta")]
    pub saas: Option<bool>,
    #[cfg(feature = "full-meta")]
    pub pricing: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryEntry {
    #[serde(default)] // 缺groups → 空数组 []
    pub groups: Vec<u32>,
    pub name: String,
    #[serde(default)]
    pub priority: u8,
}
