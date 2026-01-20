//! 工具模块：提供通用工具函数
pub mod version_extractor;
pub mod header_converter;
pub mod detection_updater;
//pub mod log_format;
pub mod extractor;


pub use self::version_extractor::VersionExtractor;
pub use self::header_converter::HeaderConverter;
pub use self::detection_updater::DetectionUpdater;
//pub use self::regex_filter::{min_evidence, prune_analyzer};
pub mod timing;


use rustc_hash::{FxHashSet};

#[inline(always)]
pub fn build_lower_hit_index<S>(hits: &FxHashSet<S>) -> FxHashSet<String>
where
    S: AsRef<str>,  // 约束：只要类型能转为 &str 即可（&str/String 都满足）
{
    // 预分配容量，避免扩容开销（保持原有高性能设计）
    let mut out = FxHashSet::with_capacity_and_hasher(hits.len(), Default::default());
    
    for h in hits {
        // 统一转为 &str 后再转小写，兼容两种类型
        out.insert(h.as_ref().to_ascii_lowercase());
    }
    
    out
}