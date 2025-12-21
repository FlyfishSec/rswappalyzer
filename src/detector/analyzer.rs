//! 检测分析器：负责URL/Header/HTML等数据的解析
use std::borrow::Cow;
use std::collections::HashMap;
use once_cell::sync::Lazy;
use regex::Regex;
use tracing::debug;

use crate::compiler::CompiledRuleLibrary;
use crate::utils::{VersionExtractor, DetectionUpdater};

/// URL分析器
pub struct UrlAnalyzer;

impl UrlAnalyzer {
    /// 分析URL提取技术
    pub fn analyze(
        compiled_lib: &CompiledRuleLibrary,
        urls: &[&str],
        detected: &mut HashMap<String, (u8, Option<String>)>,
    ) {
        for url in urls {
            for (_, compiled_tech) in &compiled_lib.tech_patterns {
                // 跳过已100%置信度的技术
                if let Some((conf, _)) = detected.get(&compiled_tech.name) {
                    if *conf >= 100 {
                        continue;
                    }
                }

                // 跳过无URL模式的技术
                let Some(url_patterns) = &compiled_tech.url_patterns else {
                    continue;
                };

                // 匹配URL模式
                for pattern in url_patterns.iter() {
                    if let Some(captures) = pattern.regex.captures(url) {
                        let version = VersionExtractor::extract(&pattern.version_template, &captures);
                        debug!(
                            "URL匹配成功：技术={}，版本={:?}，规则={}",
                            compiled_tech.name,
                            version,
                            pattern.regex.as_str()
                        );
                        DetectionUpdater::update(
                            detected,
                            compiled_tech.name.clone(),
                            Some(pattern.confidence),
                            version,
                        );
                        break; // 匹配成功后跳过该技术的其他模式
                    }
                }
            }
        }
    }
}

/// Header分析器
pub struct HeaderAnalyzer;

impl HeaderAnalyzer {
    /// 分析Header提取技术
    pub fn analyze(
        compiled_lib: &CompiledRuleLibrary,
        headers: &HashMap<String, String>,
        detected: &mut HashMap<String, (u8, Option<String>)>,
    ) {
        for (_, compiled_tech) in &compiled_lib.tech_patterns {
            // 跳过无Header模式的技术
            let Some(header_patterns) = &compiled_tech.header_patterns else {
                continue;
            };

            // 遍历Header模式
            for (header_name, patterns) in header_patterns.iter() {
                let Some(header_value) = headers.get(header_name) else {
                    continue;
                };

                // 匹配Header模式
                for pattern in patterns {
                    if let Some(captures) = pattern.regex.captures(header_value) {
                        let version = VersionExtractor::extract(&pattern.version_template, &captures);
                        debug!(
                            "Header匹配成功：技术={}，Header={}，版本={:?}，规则={}",
                            compiled_tech.name,
                            header_name,
                            version,
                            pattern.regex.as_str()
                        );
                        DetectionUpdater::update(
                            detected,
                            compiled_tech.name.clone(),
                            Some(pattern.confidence),
                            version,
                        );
                    }
                }
            }
        }
    }
}

/// HTML分析器
pub struct HtmlAnalyzer;

impl HtmlAnalyzer {
    /// 分析HTML内容提取技术
    pub fn analyze(
        compiled_lib: &CompiledRuleLibrary,
        html: &Cow<str>,
        detected: &mut HashMap<String, (u8, Option<String>)>,
    ) {
        for (_, compiled_tech) in &compiled_lib.tech_patterns {
            // 跳过无HTML模式的技术
            let Some(html_patterns) = &compiled_tech.html_patterns else {
                continue;
            };

            // 匹配HTML模式
            for pattern in html_patterns.iter() {
                if let Some(captures) = pattern.regex.captures(html) {
                    let version = VersionExtractor::extract(&pattern.version_template, &captures);
                    DetectionUpdater::update(
                        detected,
                        compiled_tech.name.clone(),
                        Some(pattern.confidence),
                        version,
                    );
                }
            }
        }
    }
}

/// Script分析器
pub struct ScriptAnalyzer;

impl ScriptAnalyzer {
    /// 分析Script-SRC提取技术
    pub fn analyze(
        compiled_lib: &CompiledRuleLibrary,
        script_srcs: &[String],
        detected: &mut HashMap<String, (u8, Option<String>)>,
    ) {
        static JQUERY_VERSION_REGEX: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"jquery-(\d+\.\d+\.\d+)|\/(\d+\.\d+\.\d+)\/jquery"#).unwrap()
        });

        for src in script_srcs {
            // 提取jQuery版本
            let jquery_version = JQUERY_VERSION_REGEX.captures(src).and_then(|cap| {
                cap.get(1).map(|m| m.as_str().to_string()).or_else(|| cap.get(2).map(|m| m.as_str().to_string()))
            });

            // 匹配Script模式
            for (_, compiled_tech) in &compiled_lib.tech_patterns {
                let Some(script_patterns) = &compiled_tech.script_patterns else {
                    continue;
                };

                for pattern in script_patterns.iter() {
                    if pattern.regex.is_match(src) {
                        let version = if compiled_tech.name == "jQuery" {
                            jquery_version.clone()
                        } else {
                            pattern.regex.captures(src).and_then(|cap| {
                                VersionExtractor::extract(&pattern.version_template, &cap)
                            })
                        };

                        DetectionUpdater::update(
                            detected,
                            compiled_tech.name.clone(),
                            Some(pattern.confidence),
                            version,
                        );
                    }
                }
            }
        }
    }
}

/// Meta分析器
pub struct MetaAnalyzer;

impl MetaAnalyzer {
    /// 分析Meta标签提取技术
    pub fn analyze(
        compiled_lib: &CompiledRuleLibrary,
        meta_tags: &[(String, String)],
        detected: &mut HashMap<String, (u8, Option<String>)>,
    ) {
        for (meta_name, content) in meta_tags {
            for (_, compiled_tech) in &compiled_lib.tech_patterns {
                let Some(meta_patterns) = &compiled_tech.meta_patterns else {
                    continue;
                };

                let Some(patterns) = meta_patterns.get(meta_name) else {
                    continue;
                };

                for pattern in patterns {
                    if let Some(captures) = pattern.regex.captures(content) {
                        let version = VersionExtractor::extract(&pattern.version_template, &captures);
                        DetectionUpdater::update(
                            detected,
                            compiled_tech.name.clone(),
                            Some(pattern.confidence),
                            version,
                        );
                    }
                }
            }
        }
    }
}