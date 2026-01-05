use serde::{Deserialize, Serialize};

/// ETag 记录（单个远程源）
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ETagRecord {
    /// 远程源名称
    pub source_name: String,
    /// 远程文件 ETag
    pub etag: String,
    /// 本地原始文件路径
    pub local_file_path: String,
    /// 最后更新时间（时间戳）
    pub last_update: u64,
}

/// ETag 总记录（序列化到本地文件）
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ETagTotalRecord {
    pub records: Vec<ETagRecord>,
}

impl ETagTotalRecord {
    /// 根据源名称查找 ETag 记录
    pub fn find_record(&self, source_name: &str) -> Option<&ETagRecord> {
        self.records.iter().find(|r| r.source_name == source_name)
    }

    /// 添加/更新 ETag 记录
    pub fn upsert_record(&mut self, new_record: ETagRecord) {
        // 移除旧记录
        self.records.retain(|r| r.source_name != new_record.source_name);
        // 添加新记录
        self.records.push(new_record);
    }
}