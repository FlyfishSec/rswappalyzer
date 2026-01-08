use std::fs;
use std::path::{PathBuf};
use crate::{RuleConfig};

/// 规则路径管理器
#[derive(Default)]
pub struct RulePathManager;

impl RulePathManager {
    /// 获取 ETag 记录文件路径（缓存根目录/etag_records.json）
    pub fn get_etag_record_path(&self, config: &RuleConfig) -> PathBuf {
        self.ensure_cache_dir_exists(config);
        config.options.cache_dir.join("etag_records.json")
    }

    /// 获取原始文件缓存目录（缓存根目录/raw_files）
    pub fn get_raw_file_cache_dir(&self, config: &RuleConfig) -> PathBuf {
        self.ensure_cache_dir_exists(config);
        let dir = config.options.cache_dir.join("raw_files");
        
        if !dir.exists() {
            let _ = fs::create_dir_all(&dir);
        }
        dir
    }

    /// 生成本地原始文件路径（复用RuleConfig已有的文件名逻辑，无重复哈希）
    pub fn generate_local_raw_file_path(&self, config: &RuleConfig) -> PathBuf {
        let raw_dir = self.get_raw_file_cache_dir(config);
        // 核心：直接从RuleConfig获取已生成的文件名（含URL哈希），只替换目录为raw_files
        let cache_file_path = config.get_cache_file_path();
        let file_name = cache_file_path.file_name().unwrap(); // 提取文件名（如custom_123456.json）
        
        raw_dir.join(file_name) // 拼接为：raw_files/文件名
    }

    /// 统一确保缓存目录存在
    fn ensure_cache_dir_exists(&self, config: &RuleConfig) {
        let cache_dir = &config.options.cache_dir;
        if !cache_dir.exists() {
            let _ = fs::create_dir_all(cache_dir);
        }
    }

    /// 关联 RuleConfig 的缓存文件路径（统一路径入口）
    pub fn get_rule_cache_file_path(&self, config: &RuleConfig) -> PathBuf {
        self.ensure_cache_dir_exists(config);
        config.get_cache_file_path()
    }
}