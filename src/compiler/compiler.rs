//! 规则编译器核心
//! 仅负责将原始规则编译为可执行的正则模式

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use regex::{Regex, Error as RegexError};
use once_cell::sync::Lazy;
use serde_json::Value;
use tracing::debug;

use super::pattern::{CompiledPattern, CompiledTechRule, CompiledRuleLibrary};
use crate::rule::{RuleLibrary, TechRule};
use crate::error::{RswResult, RswappalyzerError};

/// 规则编译器
pub struct RuleCompiler;

impl RuleCompiler {
    /// 编译规则库
    pub fn compile(rule_lib: &RuleLibrary) -> RswResult<CompiledRuleLibrary> {
        let start = Instant::now();
        let mut compiled_tech_rules = HashMap::new();
        let mut category_map = HashMap::new();

        // 1. 构建分类映射（ID -> 名称）
        for (_, cat_rule) in &rule_lib.category_rules {
            category_map.insert(cat_rule.id, cat_rule.name.clone());
        }

        // 2. 编译每个技术规则
        let mut compile_stats = CompileStats::default();
        for (tech_name, tech_rule) in &rule_lib.tech_rules {
            let compiled_tech = Self::compile_tech_rule(tech_name, tech_rule, &mut compile_stats)?;
            compiled_tech_rules.insert(tech_name.clone(), compiled_tech);
        }

        // 3. 输出编译统计
        let total_time = start.elapsed();
        debug!("✅ 规则编译完成，总耗时{:?}", total_time);
        debug!(
            "📊 编译统计：URL模式{}条、HTML模式{}条、Script模式{}条、Header模式{}条、Meta模式{}条",
            compile_stats.url_count,
            compile_stats.html_count,
            compile_stats.script_count,
            compile_stats.header_count,
            compile_stats.meta_count
        );

        Ok(CompiledRuleLibrary {
            tech_patterns: compiled_tech_rules,
            category_map,
        })
    }

    /// 编译单个技术规则
    fn compile_tech_rule(
        tech_name: &str,
        tech_rule: &TechRule,
        stats: &mut CompileStats,
    ) -> RswResult<CompiledTechRule> {
        // 编译各类模式
        let url_patterns = Self::compile_pattern_list(tech_rule.url.as_ref(), stats, "url")?;
        let html_patterns = Self::compile_pattern_list(tech_rule.html.as_ref(), stats, "html")?;
        let script_patterns = Self::compile_script_patterns(tech_rule, stats)?;
        let meta_patterns = Self::compile_keyed_patterns(tech_rule.meta.as_ref(), stats, "meta")?;
        let header_patterns = Self::compile_keyed_patterns(tech_rule.headers.as_ref(), stats, "header")?;

        Ok(CompiledTechRule {
            name: tech_name.to_string(),
            url_patterns: url_patterns.map(Arc::new),
            html_patterns: html_patterns.map(Arc::new),
            script_patterns: script_patterns.map(Arc::new),
            meta_patterns: meta_patterns.map(Arc::new),
            header_patterns: header_patterns.map(Arc::new),
            category_ids: tech_rule.category_ids.clone(),
            website: tech_rule.website.clone(),
            description: tech_rule.description.clone(),
            icon: tech_rule.icon.clone(),
            cpe: tech_rule.cpe.clone(),
            saas: tech_rule.saas,
            pricing: tech_rule.pricing.clone(),
        })
    }

    /// 编译列表型模式（url/html/script等）
    fn compile_pattern_list(
        value: Option<&Value>,
        stats: &mut CompileStats,
        pattern_type: &str,
    ) -> RswResult<Option<Vec<CompiledPattern>>> {
        let Some(value) = value else {
            return Ok(None);
        };

        let mut patterns = Vec::new();
        match value {
            Value::String(s) => {
                if let Ok(pattern) = Self::compile_single_pattern(s) {
                    patterns.push(pattern);
                    Self::update_stats(stats, pattern_type, 1);
                }
            }
            Value::Array(arr) => {
                for item in arr {
                    if let Value::String(s) = item {
                        if let Ok(pattern) = Self::compile_single_pattern(s) {
                            patterns.push(pattern);
                            Self::update_stats(stats, pattern_type, 1);
                        }
                    }
                }
            }
            _ => {
                return Err(RswappalyzerError::RegexCompileError(
                    RegexError::Syntax(format!("{}规则类型不支持", pattern_type))
                ));
            }
        }

        if patterns.is_empty() {
            Ok(None)
        } else {
            Ok(Some(patterns))
        }
    }

    /// 编译Script模式（合并script和script_src）
    fn compile_script_patterns(
        tech_rule: &TechRule,
        stats: &mut CompileStats,
    ) -> RswResult<Option<Vec<CompiledPattern>>> {
        let mut patterns = Vec::new();

        // 编译script规则
        if let Some(script_value) = tech_rule.scripts.as_ref() {
            if let Some(mut script_patterns) = Self::compile_pattern_list(Some(script_value), stats, "script")? {
                patterns.append(&mut script_patterns);
            }
        }

        // 编译script_src规则
        if let Some(script_src_value) = tech_rule.script_src.as_ref() {
            if let Some(mut script_src_patterns) = Self::compile_pattern_list(Some(script_src_value), stats, "script")? {
                patterns.append(&mut script_src_patterns);
            }
        }

        if patterns.is_empty() {
            Ok(None)
        } else {
            Ok(Some(patterns))
        }
    }

    /// 编译键值对型模式（meta/header）
    fn compile_keyed_patterns(
        value: Option<&HashMap<String, Value>>,
        stats: &mut CompileStats,
        pattern_type: &str,
    ) -> RswResult<Option<HashMap<String, Vec<CompiledPattern>>>> {
        let Some(value) = value else {
            return Ok(None);
        };

        let mut keyed_patterns = HashMap::new();
        for (key, val) in value {
            if let Some(patterns) = Self::compile_pattern_list(Some(val), stats, pattern_type)? {
                let count = patterns.len();
                keyed_patterns.insert(key.to_lowercase(), patterns);
                Self::update_stats(stats, pattern_type, count);
            }
        }

        if keyed_patterns.is_empty() {
            Ok(None)
        } else {
            Ok(Some(keyed_patterns))
        }
    }

    /// 编译单个正则模式（修复Wappalyzer正则兼容性问题）
    fn compile_single_pattern(raw_pattern: &str) -> RswResult<CompiledPattern> {
        static LOOK_AROUND_REGEX: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"\s*\(\?[=!<>].*?\)\s*"#).unwrap()
        });
        static VERSION_MARKER_REGEX: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(\\?;version:\\?\d+)"#).unwrap()
        });

        // 1. 提取版本模板
        let version_template = if raw_pattern.contains(";version:") {
            let parts: Vec<&str> = raw_pattern.splitn(2, ";version:").collect();
            parts.get(1).map(|v| v.to_string())
        } else {
            None
        };

        // 2. 清理原始正则
        let mut cleaned_pattern = raw_pattern.to_string();

        // 移除PCRE分隔符
        if cleaned_pattern.starts_with('/') && cleaned_pattern.ends_with('/') {
            cleaned_pattern = cleaned_pattern[1..cleaned_pattern.len()-1].to_string();
        }

        // 移除环视语法
        cleaned_pattern = LOOK_AROUND_REGEX.replace_all(&cleaned_pattern, "").to_string();

        // 清理无效转义
        cleaned_pattern = Self::clean_invalid_escapes(&cleaned_pattern);

        // 修复字符集无效连字符
        cleaned_pattern = Self::fix_charset_hyphen(&cleaned_pattern);

        // 修复未闭合分组
        cleaned_pattern = Self::fix_unbalanced_groups(&cleaned_pattern);

        // 移除版本标记
        cleaned_pattern = VERSION_MARKER_REGEX.replace_all(&cleaned_pattern, "").to_string();

        // 3. 编译正则
        let regex = Regex::new(&cleaned_pattern)?;

        Ok(CompiledPattern {
            regex,
            confidence: 100,
            version_template,
        })
    }

    /// 清理无效转义符
    fn clean_invalid_escapes(s: &str) -> String {
        let mut cleaned = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.peek() {
                    Some(next_c) if matches!(next_c, 'd' | 'D' | 'w' | 'W' | 's' | 'S' | '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '/') => {
                        cleaned.push(c);
                        cleaned.push(*next_c);
                        chars.next();
                    }
                    _ => {
                        if let Some(next_c) = chars.peek() {
                            cleaned.push(*next_c);
                            chars.next();
                        }
                    }
                }
            } else {
                cleaned.push(c);
            }
        }

        cleaned
    }

    /// 修复字符集中的无效连字符
    fn fix_charset_hyphen(s: &str) -> String {
        let mut chars = s.chars().peekable();
        let mut result = String::with_capacity(s.len());
        let mut in_charset = false;

        while let Some(c) = chars.next() {
            match c {
                '[' => {
                    in_charset = true;
                    result.push(c);
                }
                ']' => {
                    in_charset = false;
                    result.push(c);
                }
                '-' if in_charset => {
                    let is_first = result.ends_with('[');
                    let mut is_last = false;
                    while let Some(&next_c) = chars.peek() {
                        if next_c == ']' {
                            is_last = true;
                            break;
                        } else if next_c.is_whitespace() {
                            chars.next();
                        } else {
                            break;
                        }
                    }

                    if is_first || is_last {
                        result.push('-');
                    } else {
                        result.push_str("\\-");
                    }
                }
                _ => {
                    result.push(c);
                }
            }
        }

        result
    }

    /// 修复未闭合分组
    fn fix_unbalanced_groups(s: &str) -> String {
        let mut chars = s.chars().peekable();
        let mut result = String::with_capacity(s.len());
        let mut group_count = 0;
        let mut ignore = false;

        while let Some(c) = chars.next() {
            if ignore {
                ignore = false;
                result.push(c);
                continue;
            }

            match c {
                '\\' => {
                    if let Some(&next_c) = chars.peek() {
                        if next_c == '(' || next_c == ')' {
                            ignore = true;
                        }
                    }
                    result.push(c);
                }
                '(' => {
                    group_count += 1;
                    result.push(c);
                }
                ')' => {
                    if group_count > 0 {
                        group_count -= 1;
                        result.push(c);
                    }
                }
                _ => {
                    result.push(c);
                }
            }
        }

        // 移除多余的未闭合分组
        let mut result_chars: Vec<char> = result.chars().collect();
        let mut i = result_chars.len();
        while i > 0 && group_count > 0 {
            i -= 1;
            if result_chars[i] == '(' && (i == 0 || result_chars[i-1] != '\\') {
                result_chars.remove(i);
                group_count -= 1;
            }
        }

        result_chars.into_iter().collect()
    }

    /// 更新编译统计
    fn update_stats(stats: &mut CompileStats, pattern_type: &str, count: usize) {
        match pattern_type {
            "url" => stats.url_count += count,
            "html" => stats.html_count += count,
            "script" => stats.script_count += count,
            "header" => stats.header_count += count,
            "meta" => stats.meta_count += count,
            _ => {}
        }
    }
}

/// 编译统计信息
#[derive(Debug, Clone, Default)]
struct CompileStats {
    url_count: usize,
    html_count: usize,
    script_count: usize,
    header_count: usize,
    meta_count: usize,
}