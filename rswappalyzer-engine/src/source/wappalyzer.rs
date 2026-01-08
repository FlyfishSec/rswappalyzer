use crate::cleaner::clean_stats::CleanStats;
use crate::core::{CategoryRule, ParsedTechRule, RuleLibrary, TechBasicInfo};
use crate::{KeyedPattern, MatchCondition, MatchRuleSet, MatchScope, MatchType, Pattern};
use rustc_hash::FxHashMap as HashMap;
use serde::{Deserialize, Serialize};
use serde_json::{self, Value};
use std::error::Error;

/// Wappalyzer 原始分类规则
/// 对应JSON结构中的categories字段，描述技术分类信息
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WappalyzerOriginalCategory {
    /// 分类名称（如"CMS"、"Web Server"）
    pub name: String,
    /// 分类优先级（可选，用于排序）
    pub priority: Option<u32>,
}

/// Wappalyzer 原始技术规则
/// 对应JSON结构中的technologies/apps字段，描述单个技术的匹配规则
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WappalyzerOriginalTechRule {
    /// 技术描述（可选）
    #[serde(default)]
    pub description: Option<String>,
    /// 技术官网地址（可选）
    #[serde(default)]
    pub website: Option<String>,
    /// 所属分类ID列表（映射到categories）
    #[serde(rename = "cats", default)]
    pub category_ids: Vec<u32>,
    /// 技术图标名称（可选）
    #[serde(default)]
    pub icon: Option<String>,
    /// CPE标识（Common Platform Enumeration，可选）
    #[serde(default)]
    pub cpe: Option<String>,
    /// 是否为SaaS服务（可选）
    #[serde(default)]
    pub saas: Option<bool>,
    /// 定价模式（可选，如["free", "paid"]）
    #[serde(default)]
    pub pricing: Option<Vec<String>>,

    /// URL匹配规则（支持字符串/数组格式，可选）
    #[serde(default)]
    pub url: Option<Value>,
    /// HTML内容匹配规则（支持字符串/数组格式，可选）
    #[serde(default)]
    pub html: Option<Value>,
    /// Script内容匹配规则（支持字符串/数组格式，可选）
    #[serde(default)]
    pub scripts: Option<Value>,
    /// Script SRC属性匹配规则（支持字符串/数组格式，可选）
    #[serde(rename = "scriptSrc", default)]
    pub script_src: Option<Value>,
    /// Meta标签匹配规则（KV结构，可选）
    #[serde(default)]
    pub meta: Option<HashMap<String, Value>>,
    /// HTTP头匹配规则（KV结构，可选）
    #[serde(default)]
    pub headers: Option<HashMap<String, Value>>,
    /// Cookie匹配规则（KV结构，可选）
    #[serde(default)]
    pub cookies: Option<HashMap<String, Value>>,
    /// JS变量匹配规则（KV结构，可选）
    #[serde(default)]
    pub js: Option<HashMap<String, Value>>,

    /// 隐含技术关联（支持字符串/数组格式，可选）
    #[serde(default)]
    pub implies: Option<Value>,

    /// 扩展字段（兼容未定义的JSON字段）
    #[serde(flatten)]
    pub extra_fields: HashMap<String, Value>,
}

/// Wappalyzer 原始规则库
/// 对应完整的Wappalyzer JSON配置结构
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WappalyzerOriginalRuleLibrary {
    /// 技术规则集合（兼容technologies/apps两种字段名）
    #[serde(rename = "technologies", alias = "apps")]
    pub technologies: HashMap<String, WappalyzerOriginalTechRule>,
    /// 分类规则集合（默认空）
    #[serde(default)]
    pub categories: HashMap<u32, WappalyzerOriginalCategory>,
}

/// Wappalyzer 规则解析器
/// 职责：将Wappalyzer JSON格式规则转换为内核可识别的RuleLibrary
#[derive(Debug, Clone, Default)]
pub struct WappalyzerParser;

impl WappalyzerParser {
    /// 创建解析器实例
    pub fn new() -> Self {
        Self::default()
    }

    /// 解析字符串格式的Wappalyzer规则
    /// 参数：content - JSON字符串
    /// 返回：原始规则库 | 解析错误
    pub fn parse(&self, content: &str) -> Result<WappalyzerOriginalRuleLibrary, Box<dyn Error>> {
        self.parse_from_str(content)
    }

    /// 从字符串解析原始规则库
    pub fn parse_from_str(
        &self,
        content: &str,
    ) -> Result<WappalyzerOriginalRuleLibrary, Box<dyn Error>> {
        serde_json::from_str(content)
            .map_err(|e| format!("Failed to parse Wappalyzer JSON string: {}", e).into())
    }

    /// 从字节流解析原始规则库
    pub fn parse_from_bytes(
        &self,
        bytes: &[u8],
    ) -> Result<WappalyzerOriginalRuleLibrary, Box<dyn Error>> {
        serde_json::from_slice(bytes)
            .map_err(|e| format!("Failed to parse Wappalyzer byte stream: {}", e).into())
    }

    /// 从serde_json::Value解析原始规则库
    pub fn parse_from_value(
        &self,
        value: &Value,
    ) -> Result<WappalyzerOriginalRuleLibrary, Box<dyn Error>> {
        serde_json::from_value(value.clone())
            .map_err(|e| format!("Failed to parse Wappalyzer JSON Value: {}", e).into())
    }

    /// 解析并转换为内核规则库
    /// 参数：content - JSON字符串
    /// 返回：内核规则库 | 解析/转换错误
    pub fn parse_to_rule_lib(&self, content: &str) -> Result<RuleLibrary, Box<dyn Error>> {
        let original = self.parse_from_str(content)?;
        Ok(self.convert_original_to_rule_lib(original))
    }

    /// 将原始规则库转换为内核规则库
    /// 参数：original - 原始Wappalyzer规则库
    /// 返回：内核可识别的RuleLibrary
    pub fn convert_original_to_rule_lib(
        &self,
        original: WappalyzerOriginalRuleLibrary,
    ) -> RuleLibrary {
        let mut _clean_stats = CleanStats::default();

        // 将implies字段的Value转换为字符串列表（兼容单字符串/数组格式）
        fn implies_value_to_vec(implies_val: &Option<Value>) -> Option<Vec<String>> {
            let Some(val) = implies_val else {
                return None;
            };

            let mut res = Vec::new();
            match val {
                Value::Array(arr) => {
                    for item in arr {
                        if let Value::String(s) = item {
                            let s_trimmed = s.trim().to_string();
                            if !s_trimmed.is_empty() {
                                res.push(s_trimmed);
                            }
                        }
                    }
                }
                Value::String(s) => {
                    let s_trimmed = s.trim().to_string();
                    if !s_trimmed.is_empty() {
                        res.push(s_trimmed);
                    }
                }
                _ => {}
            }

            (!res.is_empty()).then_some(res)
        }

        // 将JSON Value转换为Pattern列表（兼容单字符串/数组格式）
        fn json_val_to_pattern_list(val: &Option<Value>) -> Vec<Pattern> {
            let mut patterns = Vec::new();
            let Some(val) = val else {
                return patterns;
            };

            match val {
                Value::Array(arr) => {
                    for item in arr {
                        if let Value::String(s) = item {
                            let s_trimmed = s.trim().to_string();
                            if !s_trimmed.is_empty() {
                                patterns.push(Pattern {
                                    pattern: s_trimmed,
                                    match_type: MatchType::Contains,
                                    version_template: None,
                                });
                            }
                        }
                    }
                }
                Value::String(s) => {
                    let s_trimmed = s.trim().to_string();
                    if !s_trimmed.is_empty() {
                        patterns.push(Pattern {
                            pattern: s_trimmed,
                            match_type: MatchType::Contains,
                            version_template: None,
                        });
                    }
                }
                _ => {}
            }

            patterns
        }

        // 批量插入列表型匹配规则到HashMap
        fn batch_insert_list_rules(
            match_rules: &mut HashMap<MatchScope, MatchRuleSet>,
            rules: Vec<Option<(MatchScope, MatchRuleSet)>>,
        ) {
            rules.into_iter().flatten().for_each(|(k, v)| {
                match_rules.insert(k, v);
            });
        }

        // 构建列表型匹配规则集（支持condition字段解析）
        fn build_list_match_rule_set(
            rule_obj: &Option<Value>,
            _scope_name: &str,
            scope: MatchScope,
        ) -> Option<(MatchScope, MatchRuleSet)> {
            let pattern_list = json_val_to_pattern_list(rule_obj);
            if pattern_list.is_empty() {
                return None;
            }

            // 解析condition字段（无则默认Or）
            let condition = match rule_obj {
                Some(Value::Object(obj)) => obj
                    .get("condition")
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

        // 构建KV型匹配规则集（用于meta/header/cookie/js）
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
                                let s_trimmed = s.trim().to_string();
                                if !s_trimmed.is_empty() {
                                    keyed_patterns.push(KeyedPattern {
                                        key: key.clone(),
                                        pattern: Pattern {
                                            pattern: s_trimmed,
                                            match_type: MatchType::Contains,
                                            version_template: None,
                                        },
                                    });
                                }
                            }
                        }
                    }
                    Value::String(s) => {
                        let s_trimmed = s.trim().to_string();
                        keyed_patterns.push(KeyedPattern {
                            key: key.clone(),
                            pattern: Pattern {
                                pattern: s_trimmed,
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
                _clean_stats.total_original_tech_rules += 1;

                // 构建技术基础信息
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

                // 处理列表型规则（URL/HTML/Script/ScriptSrc）
                let list_rules = vec![
                    build_list_match_rule_set(&original_tech.url, "url", MatchScope::Url),
                    build_list_match_rule_set(&original_tech.html, "html", MatchScope::Html),
                    build_list_match_rule_set(&original_tech.scripts, "script", MatchScope::Script),
                    build_list_match_rule_set(
                        &original_tech.script_src,
                        "script_src",
                        MatchScope::ScriptSrc,
                    ),
                ];
                batch_insert_list_rules(&mut match_rules, list_rules);

                // 处理Meta匹配规则（支持condition字段）
                if let Some(meta_map) = &original_tech.meta {
                    let keyed_patterns = build_keyed_match_rule_set(meta_map, "meta");
                    if !keyed_patterns.is_empty() {
                        let meta_condition = original_tech
                            .meta
                            .as_ref()
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

                // 处理Header匹配规则（支持condition字段）
                if let Some(header_map) = &original_tech.headers {
                    let header_keyed_patterns = build_keyed_match_rule_set(header_map, "header");
                    if !header_keyed_patterns.is_empty() {
                        let header_condition = original_tech
                            .headers
                            .as_ref()
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

                // 处理Cookie匹配规则（支持condition字段）
                if let Some(cookie_map) = &original_tech.cookies {
                    let cookie_keyed_patterns = build_keyed_match_rule_set(cookie_map, "cookie");
                    if !cookie_keyed_patterns.is_empty() {
                        let cookie_condition = original_tech
                            .cookies
                            .as_ref()
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

                // 处理JS匹配规则（支持condition字段）
                if let Some(js_map) = &original_tech.js {
                    let js_keyed_patterns = build_keyed_match_rule_set(js_map, "js");
                    if !js_keyed_patterns.is_empty() {
                        let js_condition = original_tech
                            .js
                            .as_ref()
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

                // 构建解析后的技术规则（过滤无匹配规则的项）
                let parsed_tech_rule = ParsedTechRule {
                    basic,
                    match_rules: if match_rules.is_empty() {
                        HashMap::default()
                    } else {
                        match_rules
                    },
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

        // 构建内核规则库
        RuleLibrary {
            core_tech_map,
            category_rules,
        }
    }
}
