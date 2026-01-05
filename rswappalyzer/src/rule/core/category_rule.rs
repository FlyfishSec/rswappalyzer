//! 通用分类规则模型
//! 收敛多源分类规则

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// 分类规则定义（通用，多源解析后统一结构）
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CategoryRule {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub priority: Option<u32>,
    #[serde(default)]
    pub id: u32,
}

/// 获取默认分类
pub fn get_default_categories() -> HashMap<u32, CategoryRule> {
    let mut categories = HashMap::new();
    let default_cats = vec![
        (1, "CMS"), (2, "Message Boards"), (3, "Database Managers"), (4, "Documentation"),
        (5, "Widgets"), (6, "Ecommerce"), (7, "Photo Galleries"), (8, "Wikis"),
        (9, "Hosting Panels"), (10, "Analytics"), (11, "Blogs"), (12, "JavaScript Frameworks"),
        (13, "Issue Trackers"), (14, "Video Players"), (15, "Comment Systems"), (16, "Security"),
        (17, "Font Scripts"), (18, "Web Frameworks"), (19, "Miscellaneous"), (20, "Editors"),
    ];

    for (id, name) in default_cats {
        categories.insert(id, CategoryRule {
            name: name.to_string(),
            priority: Some(id),
            id,
        });
    }

    categories
}