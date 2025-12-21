//! 编译后模式模型
//! 正则编译后的结构

use std::collections::HashMap;
use std::sync::Arc;
use regex::Regex;

/// 编译后的正则模式
#[derive(Debug, Clone)]
pub struct CompiledPattern {
    pub regex: Regex,
    pub confidence: u8,
    pub version_template: Option<String>,
}

/// 技术编译后的规则
#[derive(Debug, Clone)]
pub struct CompiledTechRule {
    pub name: String,
    pub url_patterns: Option<Arc<Vec<CompiledPattern>>>,
    pub html_patterns: Option<Arc<Vec<CompiledPattern>>>,
    pub script_patterns: Option<Arc<Vec<CompiledPattern>>>,
    pub meta_patterns: Option<Arc<HashMap<String, Vec<CompiledPattern>>>>,
    pub header_patterns: Option<Arc<HashMap<String, Vec<CompiledPattern>>>>,
    pub category_ids: Vec<u32>,
    pub website: Option<String>,
    pub description: Option<String>,
    pub icon: Option<String>,
    pub cpe: Option<String>,
    pub saas: Option<bool>,
    pub pricing: Option<Vec<String>>,
}

/// 编译后的规则库
#[derive(Debug, Clone)]
pub struct CompiledRuleLibrary {
    pub tech_patterns: HashMap<String, CompiledTechRule>,
    pub category_map: HashMap<u32, String>, // 分类ID -> 分类名称
}