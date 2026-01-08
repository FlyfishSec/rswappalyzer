// src/rule/loader/etag_manager.rs
use std::fs;
use log::debug;
use crate::RuleConfig;
use crate::error::{RswResult};
use crate::rule::loader::etag::{ETagRecord, ETagTotalRecord};
use crate::rule::loader::path_manager::RulePathManager;

/// ETag 记录管理器
#[derive(Default)]
pub struct EtagManager {
    path_manager: RulePathManager,
}

impl EtagManager {
    /// 加载 ETag 记录
    pub fn load_etag_records(&self, config: &RuleConfig) -> RswResult<ETagTotalRecord> {
        let etag_path = self.path_manager.get_etag_record_path(config);
        if !etag_path.exists() {
            return Ok(ETagTotalRecord::default());
        }

        let content = fs::read_to_string(&etag_path)?;
        let records = serde_json::from_str(&content)?;
        Ok(records)
    }

    /// 保存 ETag 记录
    pub fn save_etag_records(&self, config: &RuleConfig, etag_records: &ETagTotalRecord) -> RswResult<()> {
        let etag_path = self.path_manager.get_etag_record_path(config);
        if let Some(parent) = etag_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        let content = serde_json::to_string_pretty(etag_records)?;
        fs::write(&etag_path, content)?;
        debug!("ETag save to：{}", etag_path.display());
        Ok(())
    }

    /// 根据源名称查询本地 ETag 记录
    pub fn find_local_etag(&self, config: &RuleConfig, source_name: &str) -> RswResult<Option<ETagRecord>> {
        let etag_total = self.load_etag_records(config)?;
        Ok(etag_total.find_record(source_name).cloned())
    }

    /// 更新并保存 ETag 记录
    pub fn upsert_and_save_etag(
        &self,
        config: &RuleConfig,
        etag_total: &mut ETagTotalRecord,
        source_name: &str,
        etag: String,
        local_file_path: String,
    ) -> RswResult<()> {
        let new_record = ETagRecord {
            source_name: source_name.to_string(),
            etag,
            local_file_path,
            last_update: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        };
        etag_total.upsert_record(new_record);
        self.save_etag_records(config, etag_total)
    }
}