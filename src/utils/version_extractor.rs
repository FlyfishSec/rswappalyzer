//! 版本提取工具
//! 从正则捕获中提取版本信息

use regex::Captures;

/// 版本提取工具
pub struct VersionExtractor;

impl VersionExtractor {
    /// 从正则捕获和版本模板中提取版本
    pub fn extract(version_template: &Option<String>, captures: &Captures) -> Option<String> {
        version_template.as_ref().and_then(|template| {
            let mut version = template.clone();
            for i in 1..captures.len() {
                if let Some(mat) = captures.get(i) {
                    version = version.replace(&format!("\\{}", i), mat.as_str());
                }
            }
            if version.is_empty() {
                None
            } else {
                Some(version)
            }
        })
    }
}