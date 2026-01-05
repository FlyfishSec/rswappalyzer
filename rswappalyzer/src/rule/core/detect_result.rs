//! 技术检测结果结构与工具函数


use serde::{Deserialize, Serialize};

/// 检测结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectResult {
    pub technologies: Vec<Technology>,
    // 推导技术列表
    // #[serde(default, skip_serializing_if = "Vec::is_empty")]
    // pub imples: Vec<String>,
}

impl std::fmt::Display for DetectResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 自定义你想要的日志格式，比如：
        write!(f, "技术栈: {:?}", self.technologies)
    }
}

/// 技术结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technology {
    pub name: String,
    pub version: Option<String>,
    pub categories: Vec<String>,
    pub confidence: u8,
    // 推导技术列表，序列化自动跳过空值
    #[serde(skip_serializing_if = "Option::is_none")]
    pub implied_by: Option<Vec<String>>, 

    // 其他可选字段
    #[cfg(feature = "full-meta")]
    pub website: Option<String>,
    #[cfg(feature = "full-meta")]
    pub description: Option<String>,
    #[cfg(feature = "full-meta")]
    pub icon: Option<String>,
    #[cfg(feature = "full-meta")]
    pub saas: Option<bool>,
    #[cfg(feature = "full-meta")]
    pub pricing: Option<Vec<String>>,
    #[cfg(feature = "full-meta")]
    pub cpe: Option<String>,
}

impl Technology {
    pub fn from_name(name: String) -> Self {
        Self {
            name,
            confidence: 50,
            version: None,
            categories: Vec::new(),
            implied_by: None,
            #[cfg(feature = "full-meta")]
            website: None,
            #[cfg(feature = "full-meta")]
            description: None,
            #[cfg(feature = "full-meta")]
            icon: None,
            #[cfg(feature = "full-meta")]
            cpe: None,
            #[cfg(feature = "full-meta")]
            saas: None,
            #[cfg(feature = "full-meta")]
            pricing: None,
        }
    }
}

impl std::fmt::Display for Technology {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.version {
            Some(v) if !v.is_empty() => write!(f, "{} {}", self.name, v),
            _ => write!(f, "{}", self.name),
        }
    }
}
