//! 编译后模式模型
//! 正则编译后的结构

use std::collections::HashMap;
use std::sync::Arc;
use regex::Regex;

#[derive(Debug, Clone)]
pub enum Matcher {
    Contains(String), // 包含匹配（忽略大小写）
    StartsWith(String), // 前缀匹配（忽略大小写）
    Regex(Regex), // 正则匹配
}

impl Matcher {
    /// 匹配输入，返回捕获结果（正则专用）
    pub fn captures<'a>(&'a self, input: &'a str) -> Option<regex::Captures<'a>> {
        match self {
            Matcher::Regex(regex) => regex.captures(input),
            _ => None, // 字符串匹配无需捕获
        }
    }

    /// 简单匹配判断
    pub fn is_match(&self, input: &str) -> bool {
        match self {
            Matcher::Contains(s) => input.to_lowercase().contains(&s.to_lowercase()),
            Matcher::StartsWith(s) => input.to_lowercase().starts_with(&s.to_lowercase()),
            Matcher::Regex(regex) => regex.is_match(input),
        }
    }

    /// 规则描述
    pub fn describe(&self) -> &str {
        match self {
            Matcher::Contains(_) => "contains",
            Matcher::StartsWith(_) => "starts_with",
            Matcher::Regex(r) => r.as_str(),
        }
    }
}

/// 编译后的正则模式
#[derive(Debug, Clone)]
pub struct CompiledPattern {
    //pub regex: Regex,
    pub matcher: Matcher,
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