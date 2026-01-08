use std::cell::RefCell;

use super::clean_stats::CleanStats;
use super::regex_fixer::RegexFixer;
use crate::core::{MatchScope, MatchType, ParsedTechRule, Pattern};
use crate::indexer::{PatternList, PatternMap};
use crate::{CoreError, CoreResult};

use regex_syntax::ast::parse::{Parser, ParserBuilder};
use regex_syntax::ast::Ast;

use serde_json::Value;
//use std::collections::HashMap;
use rustc_hash::FxHashMap;

/// 模式处理器（专门处理各类规则模式的清理与标记）
#[derive(Debug, Default)]
pub struct PatternProcessor {
    regex_fixer: RegexFixer,
    // 单线程场景,正则编译缓存 Key=原始字符串 Value=(是否有捕获组, 编译结果)
    regex_cache: RefCell<FxHashMap<String, (bool, Option<regex::Regex>)>>,
}

impl PatternProcessor {
    /// 清理并标记单个技术规则的所有模式，返回处理后的标记字段
    pub fn process_tech_rule_patterns(
        &self,
        original_tech: &ParsedTechRule,
        stats: &mut CleanStats,
    ) -> CoreResult<(
        Option<PatternList>,
        Option<PatternList>,
        Option<PatternList>,
        Option<PatternList>,
        Option<PatternMap>,
        Option<PatternMap>,
        Option<PatternMap>,
    )> {
        // 1. 处理列表型规则（Url/Html）：标准JSON解析+清理
        let url = self.build_list_pattern(original_tech, MatchScope::Url, stats, "url")?;
        let html = self.build_list_pattern(original_tech, MatchScope::Html, stats, "html")?;

        // 2. 处理列表型规则（Script/ScriptSrc）：专用清理方法，补全正则修复
        let (scripts, script_src) = self.clean_and_mark_script_patterns(original_tech, stats)?;

        // 3. 处理KV型规则（Meta/Header/Cookie）：复用统一的键值对清理逻辑
        let meta = self.build_keyed_pattern(original_tech, MatchScope::Meta, stats, "meta")?;
        let headers =
            self.build_keyed_pattern(original_tech, MatchScope::Header, stats, "header")?;
        let cookies =
            self.build_keyed_pattern(original_tech, MatchScope::Cookie, stats, "cookie")?;

        Ok((url, html, scripts, script_src, meta, headers, cookies))
    }

    /// 统一构建列表型规则
    fn build_list_pattern(
        &self,
        tech: &ParsedTechRule,
        scope: MatchScope,
        stats: &mut CleanStats,
        pat_type: &str,
    ) -> CoreResult<Option<PatternList>> {
        let Some(rule_set) = tech.match_rules.get(&scope) else {
            return Ok(None);
        };
        let pattern_strs: Vec<&str> = rule_set
            .list_patterns
            .iter()
            .map(|p| p.pattern.as_str())
            .collect();
        let patterns = self.clean_pattern_str_list(&pattern_strs, stats, pat_type)?;
        Ok(patterns.to_opt_pattern())
    }

    /// 统一构建键值对型规则
    fn build_keyed_pattern(
        &self,
        tech: &ParsedTechRule,
        scope: MatchScope,
        stats: &mut CleanStats,
        pat_type: &str,
    ) -> CoreResult<Option<PatternMap>> {
        let Some(rule_set) = tech.match_rules.get(&scope) else {
            return Ok(None);
        };
        // 直接构建字符串Map，不转Value::String
        let mut keyed_map = FxHashMap::default();
        for kp in &rule_set.keyed_patterns {
            keyed_map.insert(kp.key.clone(), kp.pattern.pattern.clone());
        }
        // 直接处理字符串Map，不走JSON解析
        let mut valid_keyed_patterns = FxHashMap::default();
        stats.update_original_pattern_stats(pat_type, keyed_map.len());
        for (key, val) in keyed_map {
            let key_lower = key.to_lowercase();
            let pat_strs = vec![val.as_str()];
            let pats = self.clean_pattern_str_list(&pat_strs, stats, pat_type)?;
            if !pats.is_empty() {
                valid_keyed_patterns.insert(key_lower, pats);
            }
        }
        Ok(valid_keyed_patterns.to_opt_pattern_map())
    }

    // 判断是否有有效模式
    // pub fn has_valid_pattern(
    //     &self,
    //     marked_url: &Option<PatternList>,
    //     marked_html: &Option<PatternList>,
    //     marked_scripts: &Option<PatternList>,
    //     marked_script_src: &Option<PatternList>,
    //     marked_meta: &Option<PatternMap>,
    //     marked_headers: &Option<PatternMap>,
    //     marked_cookies: &Option<PatternMap>,
    // ) -> bool {
    //     marked_url.is_some()
    //         || marked_html.is_some()
    //         || marked_scripts.is_some()
    //         || marked_script_src.is_some()
    //         || marked_meta.is_some()
    //         || marked_headers.is_some()
    //         || marked_cookies.is_some()
    // }

    /// 直接清理已解析的Pattern列表
    pub fn clean_and_mark_parsed_pattern_list(
        &self,
        parsed_patterns: Option<&Vec<Pattern>>,
        stats: &mut CleanStats,
        pattern_type: &str,
    ) -> CoreResult<Option<PatternList>> {
        let Some(parsed_patterns) = parsed_patterns else {
            return Ok(None);
        };

        let pattern_strs: Vec<&str> = parsed_patterns.iter().map(|p| p.pattern.as_str()).collect();
        let patterns = self.clean_pattern_str_list(&pattern_strs, stats, pattern_type)?;
        Ok(patterns.to_opt_pattern())
    }

    /// 清理并标记列表型模式（url/html/scripts/script_src）从JSON值清理列表型模式（仅解析JSON）
    pub fn clean_and_mark_list_pattern(
        &self,
        original_value: Option<&Value>,
        stats: &mut CleanStats,
        pattern_type: &str,
    ) -> CoreResult<Option<PatternList>> {
        let Some(original_value) = original_value else {
            return Ok(None);
        };

        let pattern_strs: Vec<&str> = match original_value {
            Value::String(s) => vec![s.as_str()],
            Value::Array(arr) => arr
                .iter()
                .filter_map(|item| {
                    if let Value::String(s) = item {
                        Some(s.as_str())
                    } else {
                        None
                    }
                })
                .collect(),
            _ => {
                return Err(CoreError::RuleParseError(format!(
                    "{}模式类型无效，仅支持字符串或数组",
                    pattern_type
                )));
            }
        };

        let patterns = self.clean_pattern_str_list(&pattern_strs, stats, pattern_type)?;
        Ok(patterns.to_opt_pattern())
    }

    /// 清理字符串模式列表
    fn clean_pattern_str_list(
        &self,
        pattern_strs: &[&str],
        stats: &mut CleanStats,
        pattern_type: &str,
    ) -> CoreResult<Vec<Pattern>> {
        let mut patterns = Vec::new();
        let original_count = pattern_strs.len();
        stats.update_original_pattern_stats(pattern_type, original_count);

        for s in pattern_strs {
            let s_trimmed = s.trim();
            // 规则：header/meta/cookie 类型 + 空字符串 → 标记为 Exists 存在性检测，不判定为无效！
            let is_exists_detection =
                (pattern_type == "header" || pattern_type == "meta" || pattern_type == "cookie")
                    && s_trimmed.is_empty();

            if is_exists_detection {
                patterns.push(Pattern {
                    pattern: "".to_string(),
                    match_type: MatchType::Exists,
                    version_template: None,
                });
                stats.update_valid_pattern_stats(pattern_type, 1);
                continue;
            }

            // 其他场景：空字符串判定为无效
            if s_trimmed.is_empty() {
                stats.update_invalid_regex_stats(pattern_type, 1);
                continue;
            }

            // 正常处理非空的匹配规则
            if let Some(marked_pat) = self.process_single_pattern(s_trimmed, stats)? {
                patterns.push(marked_pat);
                stats.update_valid_pattern_stats(pattern_type, 1);
            } else {
                stats.update_invalid_regex_stats(pattern_type, 1);
            }
        }

        Ok(patterns)
    }

    /// 清理并标记Script相关模式（scripts + script_src）
    pub fn clean_and_mark_script_patterns(
        &self,
        original_tech_rule: &ParsedTechRule,
        stats: &mut CleanStats,
    ) -> CoreResult<(Option<PatternList>, Option<PatternList>)> {
        let script_patterns = original_tech_rule
            .match_rules
            .get(&MatchScope::Script)
            .map(|rule_set| &rule_set.list_patterns);

        let script_src_patterns = original_tech_rule
            .match_rules
            .get(&MatchScope::ScriptSrc)
            .map(|rule_set| &rule_set.list_patterns);

        let marked_scripts =
            self.clean_and_mark_parsed_pattern_list(script_patterns, stats, "script")?;
        let marked_script_src =
            self.clean_and_mark_parsed_pattern_list(script_src_patterns, stats, "script_src")?;

        Ok((marked_scripts, marked_script_src))
    }

    /// 清理并标记键值对型模式（meta/headers/cookies）
    pub fn clean_and_mark_keyed_pattern(
        &self,
        original_value: Option<&FxHashMap<String, Value>>,
        stats: &mut CleanStats,
        pattern_type: &str,
    ) -> CoreResult<Option<PatternMap>> {
        let Some(original_value) = original_value else {
            return Ok(None);
        };

        let mut valid_keyed_patterns = FxHashMap::default();

        for (key, val) in original_value {
            let key_lower = key.to_lowercase();
            let marked_pats = self.clean_and_mark_list_pattern(Some(val), stats, pattern_type)?;
            if let Some(PatternList(pats)) = marked_pats {
                if !pats.is_empty() {
                    valid_keyed_patterns.insert(key_lower, pats);
                }
            }
        }

        Ok(valid_keyed_patterns.to_opt_pattern_map())
    }

    /// 处理单个模式（判断匹配类型、修复正则、提取版本模板）
    pub fn process_single_pattern(
        &self,
        raw_pattern: &str,
        stats: &mut CleanStats,
    ) -> CoreResult<Option<Pattern>> {
        // 第一步：先判断简单模式，直接返回，不走后续修复逻辑
        if self.regex_fixer.is_simple_contains(raw_pattern) {
            stats.contains_count += 1;
            return Ok(Some(Pattern {
                pattern: raw_pattern.to_string(),
                match_type: MatchType::Contains,
                version_template: None, // 简单模式无版本模板
            }));
        }

        // 提取版本模板
        let version_template = if raw_pattern.contains(";version:") {
            // 带 ;version: 标记的规则 → 解析自定义版本模板
            let parts: Vec<&str> = raw_pattern.splitn(2, ";version:").collect();
            parts.get(1).map(|v| v.to_string())
        } else {
            // 纯正则无标记规则 → 有捕获组则自动赋值默认模板 ${1}
            // 优先查缓存，避免重复编译
            let (has_capture, _) = self.get_regex_cache(raw_pattern)?;
            if has_capture {
                Some("${1}".to_string())
            } else {
                None
            }
        };

        let pattern_without_delimiter = self.regex_fixer.remove_pcre_delimiter(raw_pattern);
        let pattern_trimmed = pattern_without_delimiter.trim();
        if pattern_trimmed.is_empty() {
            return Ok(None);
        }

        let mut cleaned_pattern = pattern_trimmed.to_string();
        let mut is_fixed = false;

        cleaned_pattern = self.regex_fixer.remove_version_marker(&cleaned_pattern);
        cleaned_pattern = self.regex_fixer.remove_look_around(&cleaned_pattern);

        let (fixed_escapes_pattern, fixed_escapes) =
            self.regex_fixer.clean_invalid_escapes(&cleaned_pattern);
        cleaned_pattern = fixed_escapes_pattern;
        if fixed_escapes {
            stats.fixed_invalid_escapes_count += 1;
            is_fixed = true;
        }

        let (fixed_hyphen_pattern, fixed_hyphen) =
            self.regex_fixer.fix_charset_hyphen_safe(&cleaned_pattern);
        cleaned_pattern = fixed_hyphen_pattern;
        if fixed_hyphen {
            stats.fixed_charset_hyphen_count += 1;
            is_fixed = true;
        }

        let (fixed_groups_pattern, fixed_groups) =
            self.regex_fixer.fix_unbalanced_groups(&cleaned_pattern);
        cleaned_pattern = fixed_groups_pattern;
        if fixed_groups {
            stats.fixed_unbalanced_groups_count += 1;
            is_fixed = true;
        }

        let (fixed_invalid_charset_pattern, fixed_invalid_charset) =
            self.regex_fixer.fix_invalid_charset(&cleaned_pattern);
        cleaned_pattern = fixed_invalid_charset_pattern;
        if fixed_invalid_charset {
            stats.fixed_invalid_charset_count += 1;
            is_fixed = true;
        }

        let cleaned_pattern_trimmed = cleaned_pattern.trim();
        if cleaned_pattern_trimmed.is_empty() {
            return Ok(None);
        }

        // 执行正则规范化：过滤PCRE特性 + 合法性校验 + 统一格式化
        let normalized_pattern = Self::optimize_wappalyzer_regex(cleaned_pattern_trimmed);

        // 使用is_fixed变量 - 统计修复的正则总数
        if is_fixed {
            stats.fixed_regex_total_count += 1;
        }

        // 正则合法性校验 + 使用规范化后的正则字符串
        // match regex::Regex::new(&normalized_pattern) {
        //     Ok(_) => {
        //         stats.regex_count += 1;
        //         Ok(Some(Pattern {
        //             pattern: normalized_pattern,
        //             match_type: MatchType::Regex,
        //             version_template,
        //         }))
        //     }
        //     Err(e) => {
        //         eprintln!("正则模式 [{}] 修复后仍无效：{}", raw_pattern, e);
        //         Ok(None)
        //     }
        // }
        stats.regex_count += 1; // 原 StartsWith 规则归为正则统计

        Ok(Some(Pattern {
            pattern: normalized_pattern,
            match_type: MatchType::Regex,
            version_template,
        }))
    }

    // 缓存辅助方法
    fn get_regex_cache(&self, raw_pattern: &str) -> CoreResult<(bool, Option<regex::Regex>)> {
        // 使用 try_borrow_mut 避免 panic，转换为业务错误
        let mut cache = self.regex_cache.try_borrow_mut()
            .map_err(|e| CoreError::InternalError(format!(
                "正则缓存被同时借用，无法获取可变引用：{}", e
            )))?; 

        // 先查缓存
        if let Some((has_capture, re)) = cache.get(raw_pattern) {
            return Ok((*has_capture, re.clone()));
        }

        // 编译正则
        let re = regex::Regex::new(raw_pattern).ok();
        let has_capture = re.as_ref().map_or(false, |r| r.captures_len() > 1);

        // 插入缓存
        cache.insert(raw_pattern.to_string(), (has_capture, re.clone()));

        Ok((has_capture, re))
    }

    /// 规范化正则
    pub fn optimize_wappalyzer_regex(pattern: &str) -> String {
        let mut parser: Parser = ParserBuilder::new().build();
        let ast: Ast = match parser.parse(pattern) {
            Ok(ast) => ast,
            Err(_) => return pattern.to_string(),
        };
        ast.to_string()
    }
}

trait ToOptionPattern {
    fn to_opt_pattern(self) -> Option<PatternList>;
}
impl ToOptionPattern for Vec<Pattern> {
    fn to_opt_pattern(self) -> Option<PatternList> {
        if self.is_empty() {
            None
        } else {
            Some(PatternList(self))
        }
    }
}

trait ToOptionPatternMap {
    fn to_opt_pattern_map(self) -> Option<PatternMap>;
}
impl ToOptionPatternMap for FxHashMap<String, Vec<Pattern>> {
    fn to_opt_pattern_map(self) -> Option<PatternMap> {
        if self.is_empty() {
            None
        } else {
            Some(PatternMap(self))
        }
    }
}
