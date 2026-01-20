//! 技术检测结果结构与工具函数

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::json;

/// 检测结果
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DetectResult {
    pub technologies: Vec<Technology>,
    // 推导技术列表
    #[serde(skip_serializing_if = "Option::is_none")]
    pub implies: Option<Vec<String>>,
    // #[serde(default, skip_serializing_if = "Vec::is_empty")]
    // pub implies: Vec<String>,
}

impl std::fmt::Display for DetectResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "technologies: {:?}", self.technologies)
    }
}

impl DetectResult {
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// 返回所有被推导出来的技术（去重、排序）
    pub fn implied_techs(&self) -> Option<Vec<String>> {
        let mut implied: Vec<String> = self
            .technologies
            .iter()
            .filter(|t| t.is_implied())
            .map(|t| t.name.clone())
            .collect();

        if implied.is_empty() {
            None
        } else {
            implied.sort_unstable();
            implied.dedup();
            Some(implied)
        }
    }

    /// 返回 implied 技术映射：ImpliedTech -> Vec<SourceTech>
    pub fn implied_map(&self) -> HashMap<String, Vec<String>> {
        let mut map = HashMap::default();

        for tech in &self.technologies {
            if let Some(from) = &tech.implied_by {
                map.insert(tech.name.clone(), from.clone());
            }
        }

        map
    }

    /// 返回简洁 JSON Value
    pub fn to_simple_json(&self) -> serde_json::Value {
        let tech_strings: Vec<String> = self
            .technologies
            .iter()
            .map(|t| match &t.version {
                Some(v) => format!("{}:{}", t.name, v),
                None => t.name.clone(),
            })
            .collect();

        json!({ "technologies": tech_strings })
    }

    /// 返回 JSON 字符串
    pub fn to_simple_string(&self) -> String {
        self.to_simple_json().to_string()
    }

    /// 直接检测到的技术（来自指纹匹配）
    pub fn direct_techs(&self) -> Vec<String> {
        self.technologies
            .iter()
            .map(|t| match &t.version {
                Some(v) => format!("{}:{}", t.name, v),
                None => t.name.clone(),
            })
            .collect()
    }

    // 返回原始的 Vec<&Technology>
    pub fn get_raw_tech_vec(&self) -> &Vec<Technology> {
        &self.technologies
    }

    /// 返回「直接技术 + 推导技术」（去重、排序）
    pub fn tech_list(&self) -> Vec<String> {
        let mut techs: Vec<String> = self
            .technologies
            .iter()
            .map(|t| match &t.version {
                Some(v) => format!("{}:{}", t.name, v),
                None => t.name.clone(),
            })
            .collect();

        if let Some(implied) = self.implied_techs() {
            techs.extend(implied);
        }

        techs.sort_unstable();
        techs.dedup();
        techs
    }
}

/// 技术结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technology {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
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
    /// 是否为推导技术
    pub fn is_implied(&self) -> bool {
        self.implied_by.is_some()
    }

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
