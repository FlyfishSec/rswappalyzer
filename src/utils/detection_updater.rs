//! 检测结果更新工具
//! 负责更新检测结果（叠加置信度、保留版本）

use std::collections::HashMap;
use std::collections::hash_map::Entry;

/// 检测结果更新工具
pub struct DetectionUpdater;

impl DetectionUpdater {
    /// 更新检测结果
    pub fn update(
        detected: &mut HashMap<String, (u8, Option<String>)>,
        tech_name: String,
        confidence: Option<u8>,
        version: Option<String>,
    ) {
        let conf = confidence.unwrap_or(100);
    
        match detected.entry(tech_name) {
            Entry::Occupied(mut entry) => {
                let (existing_conf, existing_version) = entry.get_mut();
                *existing_conf = (*existing_conf + conf).min(100);
    
                if existing_version.is_none() {
                    *existing_version = version;
                }
            }
            Entry::Vacant(entry) => {
                entry.insert((conf, version));
            }
        }
    }
    
    /// 应用关联推导规则（implies）
    pub fn apply_implies(
        tech_rules: &HashMap<String, crate::rule::TechRule>,
        detected: &mut HashMap<String, (u8, Option<String>)>,
    ) {
        let mut implied_techs = Vec::new();

        for (tech_name, tech_rule) in tech_rules {
            if detected.contains_key(tech_name) {
                if let Some(implies) = &tech_rule.implies {
                    Self::parse_implies(implies, &mut implied_techs);
                }
            }
        }

        // 添加隐含技术
        for implied in implied_techs {
            if !detected.contains_key(&implied) {
                detected.insert(implied, (50, None));
            }
        }
    }

    /// 解析implies规则
    fn parse_implies(implies: &serde_json::Value, implied_techs: &mut Vec<String>) {
        match implies {
            serde_json::Value::String(s) => {
                for tech in s.split(',') {
                    let tech = tech.trim();
                    if !tech.is_empty() {
                        implied_techs.push(tech.to_string());
                    }
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    if let serde_json::Value::String(s) = item {
                        let tech = s.trim();
                        if !tech.is_empty() {
                            implied_techs.push(tech.to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }
}