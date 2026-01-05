use std::fs;
use std::path::{Path, PathBuf};
use crate::RuleConfig;
use crate::rule::loader::remote_source::RemoteRuleSource;

/// 规则路径管理器（专门处理路径生成与目录创建）
#[derive(Default)]
pub struct RulePathManager;

impl RulePathManager {
    /// 获取缓存根目录（rule_cache_path 的父目录）
    pub fn get_cache_root_dir(&self, config: &RuleConfig) -> PathBuf {
        let rule_cache_path = &config.options.cache_path;
        if rule_cache_path.is_file() || !rule_cache_path.exists() {
            rule_cache_path.parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf()
        } else {
            rule_cache_path.clone()
        }
    }

    /// 获取 ETag 记录文件路径（缓存根目录/etag_records.json）
    pub fn get_etag_record_path(&self, config: &RuleConfig) -> PathBuf {
        let cache_root = self.get_cache_root_dir(config);
        cache_root.join("etag_records.json")
    }

    /// 获取原始文件缓存目录（缓存根目录/raw_files）
    pub fn get_raw_file_cache_dir(&self, config: &RuleConfig) -> PathBuf {
        let cache_root = self.get_cache_root_dir(config);
        let dir = cache_root.join("raw_files");
        if !dir.exists() {
            let _ = fs::create_dir_all(&dir);
        }
        dir
    }

    /// 生成本地原始文件路径（raw_files/源名称_规则类型.后缀）
    pub fn generate_local_raw_file_path(&self, config: &RuleConfig, source: &RemoteRuleSource) -> PathBuf {
        let dir = self.get_raw_file_cache_dir(config);
        let file_suffix = source.rule_file_type.file_suffix();
        let rule_type_str = source.rule_file_type.to_str();
        let file_name = format!("{}_{}.{}", source.name, rule_type_str, file_suffix);
        dir.join(file_name)
    }
}