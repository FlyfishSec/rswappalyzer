use crate::cleaner::clean_stats::CleanStats;
use crate::core::{CategoryRule, ParsedTechRule, RuleLibrary, TechBasicInfo};
use crate::{
    KeyedPattern, MatchCondition, MatchRuleSet, MatchScope, MatchType, Pattern,
};
use serde::{Deserialize, Serialize};
use serde_json::{self, Value};
//use std::collections::HashMap;
use rustc_hash::FxHashMap as HashMap;
use std::error::Error;

/// Wappalyzer 原始分类规则
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WappalyzerOriginalCategory {
    pub name: String,
    pub priority: Option<u32>,
}

/// Wappalyzer 原始技术规则
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WappalyzerOriginalTechRule {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub website: Option<String>,
    #[serde(rename = "cats", default)]
    pub category_ids: Vec<u32>,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub cpe: Option<String>,
    #[serde(default)]
    pub saas: Option<bool>,
    #[serde(default)]
    pub pricing: Option<Vec<String>>,

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

    #[serde(default)]
    pub implies: Option<serde_json::Value>,

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

/// Wappalyzer 规则解析器
#[derive(Debug, Clone, Default)]
pub struct WappalyzerParser;

#[allow(dead_code)]
impl WappalyzerParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parse(&self, content: &str) -> Result<WappalyzerOriginalRuleLibrary, Box<dyn Error>> {
        self.parse_from_str(content)
    }

    pub fn parse_from_str(
        &self,
        content: &str,
    ) -> Result<WappalyzerOriginalRuleLibrary, Box<dyn Error>> {
        serde_json::from_str(content).map_err(|e| format!("Wappalyzer JSON解析失败: {}", e).into())
    }

    pub fn parse_from_bytes(
        &self,
        bytes: &[u8],
    ) -> Result<WappalyzerOriginalRuleLibrary, Box<dyn Error>> {
        serde_json::from_slice(bytes)
            .map_err(|e| format!("Wappalyzer 字节流解析失败: {}", e).into())
    }

    pub fn parse_from_value(
        &self,
        value: &serde_json::Value,
    ) -> Result<WappalyzerOriginalRuleLibrary, Box<dyn Error>> {
        serde_json::from_value(value.clone())
            .map_err(|e| format!("Wappalyzer JSON Value解析失败: {}", e).into())
    }

    pub fn parse_to_rule_lib(&self, content: &str) -> Result<RuleLibrary, Box<dyn Error>> {
        let original = self.parse_from_str(content)?;
        Ok(self.convert_original_to_rule_lib(original))
    }

    pub fn convert_original_to_rule_lib(
        &self,
        original: WappalyzerOriginalRuleLibrary,
    ) -> RuleLibrary {
        let mut clean_stats = CleanStats::default();

        // serde_json::Value 转 Vec<String>，兼容单字符串/数组两种格式
        fn implies_value_to_vec(implies_val: &Option<Value>) -> Option<Vec<String>> {
            let Some(val) = implies_val else {
                return None;
            };
            let mut res = Vec::new();
            match val {
                Value::Array(arr) => {
                    for item in arr {
                        if let Value::String(s) = item {
                            let s = s.trim().to_string();
                            if !s.is_empty() {
                                res.push(s);
                            }
                        }
                    }
                }
                Value::String(s) => {
                    let s = s.trim().to_string();
                    if !s.is_empty() {
                        res.push(s);
                    }
                }
                _ => {}
            }
            if res.is_empty() { None } else { Some(res) }
        }

        // 兼容：数组格式["xxx"] + 单字符串格式"xxx" 两种写法
        fn json_val_to_pattern_list(val: &Option<Value>) -> Vec<Pattern> {
            let mut patterns = Vec::new();
            let Some(val) = val else {
                return patterns;
            };
            match val {
                Value::Array(arr) => {
                    for item in arr {
                        if let Value::String(s) = item {
                            let s = s.trim().to_string();
                            if !s.is_empty() {
                                patterns.push(Pattern {
                                    pattern: s,
                                    match_type: MatchType::Contains,
                                    version_template: None,
                                });
                            }
                        }
                    }
                }
                Value::String(s) => {
                    let s = s.trim().to_string();
                    if !s.is_empty() {
                        patterns.push(Pattern {
                            pattern: s,
                            match_type: MatchType::Contains,
                            version_template: None,
                        });
                    }
                }
                _ => {}
            }
            patterns
        }

        // 批量插入列表型规则
        fn batch_insert_list_rules(
            match_rules: &mut HashMap<MatchScope, MatchRuleSet>,
            rules: Vec<Option<(MatchScope, MatchRuleSet)>>,
        ) {
            rules.into_iter().flatten().for_each(|(k, v)| {
                match_rules.insert(k, v);
            });
        }

        // ✅ 修改点1: 读取condition字段，有则用，无则默认Or (核心改动)
        fn build_list_match_rule_set(
            rule_obj: &Option<Value>,
            _scope_name: &str,
            scope: MatchScope,
        ) -> Option<(MatchScope, MatchRuleSet)> {
            let pattern_list = json_val_to_pattern_list(rule_obj);
            if pattern_list.is_empty() {
                return None;
            }
            // 读取condition字段，自动反序列化，无则用枚举默认值Or
            let condition = match rule_obj {
                Some(Value::Object(obj)) => obj.get("condition")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default(),
                _ => MatchCondition::Or,
            };
            Some((
                scope,
                MatchRuleSet {
                    condition,
                    list_patterns: pattern_list,
                    keyed_patterns: Vec::new(),
                },
            ))
        }

        fn build_keyed_match_rule_set(
            pattern_map: &HashMap<String, Value>,
            _scope_name: &str,
        ) -> Vec<KeyedPattern> {
            let mut keyed_patterns = Vec::new();

            for (k, v) in pattern_map.iter() {
                let key = k.to_lowercase();

                match v {
                    Value::Array(arr) => {
                        for item in arr {
                            if let Value::String(s) = item {
                                let s = s.trim().to_string();
                                if !s.is_empty() {
                                    keyed_patterns.push(KeyedPattern {
                                        key: key.clone(),
                                        pattern: Pattern {
                                            pattern: s,
                                            match_type: MatchType::Contains,
                                            version_template: None,
                                        },
                                    });
                                }
                            }
                        }
                    }
                    Value::String(s) => {
                        let s = s.trim().to_string();
                        keyed_patterns.push(KeyedPattern {
                            key: key.clone(),
                            pattern: Pattern {
                                pattern: s,
                                match_type: MatchType::Exists,
                                version_template: None,
                            },
                        });
                    }
                    _ => {}
                }
            }
            keyed_patterns
        }

        // 转换技术规则
        let core_tech_map = original
            .technologies
            .into_iter()
            .map(|(tech_name, original_tech)| {
                clean_stats.total_original_tech_rules += 1;

                let basic = TechBasicInfo {
                    category_ids: original_tech.category_ids,
                    implies: implies_value_to_vec(&original_tech.implies),

                    #[cfg(feature = "full-meta")]
                    tech_name: Some(tech_name.clone()),
                    #[cfg(feature = "full-meta")]
                    description: original_tech.description,
                    #[cfg(feature = "full-meta")]
                    website: original_tech.website,
                    #[cfg(feature = "full-meta")]
                    icon: original_tech.icon,
                    #[cfg(feature = "full-meta")]
                    cpe: original_tech.cpe,
                    #[cfg(feature = "full-meta")]
                    saas: original_tech.saas,
                    #[cfg(feature = "full-meta")]
                    pricing: original_tech.pricing,
                    ..TechBasicInfo::default()
                };

                let mut match_rules = HashMap::default();

                // 处理列表型规则【URL/HTML/Script/ScriptSrc】- 逻辑不变，只是用了修改后的build函数
                let list_rules = vec![
                    build_list_match_rule_set(&original_tech.url, "url", MatchScope::Url),
                    build_list_match_rule_set(&original_tech.html, "html", MatchScope::Html),
                    build_list_match_rule_set(&original_tech.scripts, "script", MatchScope::Script),
                    build_list_match_rule_set(&original_tech.script_src, "script_src", MatchScope::ScriptSrc),
                ];
                batch_insert_list_rules(&mut match_rules, list_rules);

                // ✅ 修改点2: KV型规则 读取condition字段 (meta/header/cookie/js 四处，格式一致)
                if let Some(meta_map) = &original_tech.meta {
                    let keyed_patterns = build_keyed_match_rule_set(meta_map, "meta");
                    if !keyed_patterns.is_empty() {
                        let meta_condition = original_tech.meta.as_ref()
                            .and_then(|m| m.get("condition"))
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_default();
                        match_rules.insert(
                            MatchScope::Meta,
                            MatchRuleSet {
                                condition: meta_condition,
                                list_patterns: Vec::new(),
                                keyed_patterns,
                            },
                        );
                    }
                }

                if let Some(header_map) = &original_tech.headers {
                    let header_keyed_patterns = build_keyed_match_rule_set(header_map, "header");
                    if !header_keyed_patterns.is_empty() {
                        let header_condition = original_tech.headers.as_ref()
                            .and_then(|h| h.get("condition"))
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_default();
                        match_rules.insert(
                            MatchScope::Header,
                            MatchRuleSet {
                                condition: header_condition,
                                list_patterns: Vec::new(),
                                keyed_patterns: header_keyed_patterns,
                            },
                        );
                    }
                }

                if let Some(cookie_map) = &original_tech.cookies {
                    let cookie_keyed_patterns = build_keyed_match_rule_set(cookie_map, "cookie");
                    if !cookie_keyed_patterns.is_empty() {
                        let cookie_condition = original_tech.cookies.as_ref()
                            .and_then(|c| c.get("condition"))
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_default();
                        match_rules.insert(
                            MatchScope::Cookie,
                            MatchRuleSet {
                                condition: cookie_condition,
                                list_patterns: Vec::new(),
                                keyed_patterns: cookie_keyed_patterns,
                            },
                        );
                    }
                }

                if let Some(js_map) = &original_tech.js {
                    let js_keyed_patterns = build_keyed_match_rule_set(js_map, "js");
                    if !js_keyed_patterns.is_empty() {
                        let js_condition = original_tech.js.as_ref()
                            .and_then(|j| j.get("condition"))
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_default();
                        match_rules.insert(
                            MatchScope::Js,
                            MatchRuleSet {
                                condition: js_condition,
                                list_patterns: Vec::new(),
                                keyed_patterns: js_keyed_patterns,
                            },
                        );
                    }
                }

                // 过滤无有效规则的技术项
                let parsed_tech_rule = if match_rules.is_empty() {
                    ParsedTechRule {
                        basic,
                        match_rules: HashMap::default(),
                    }
                } else {
                    ParsedTechRule { basic, match_rules }
                };

                (tech_name, parsed_tech_rule)
            })
            .collect();

        // 转换分类规则
        let category_rules = original
            .categories
            .into_iter()
            .map(|(cat_id, original_cat)| {
                (
                    cat_id,
                    CategoryRule {
                        id: cat_id,
                        name: original_cat.name,
                        priority: original_cat.priority,
                    },
                )
            })
            .collect();

        RuleLibrary {
            core_tech_map,
            category_rules,
        }
    }
}