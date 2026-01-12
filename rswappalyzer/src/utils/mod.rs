//! 工具模块：提供通用工具函数
pub mod version_extractor;
pub mod header_converter;
pub mod detection_updater;
//pub mod log_format;
pub mod extractor;

use rustc_hash::FxHashSet;

pub use self::version_extractor::VersionExtractor;
pub use self::header_converter::HeaderConverter;
pub use self::detection_updater::DetectionUpdater;
//pub use self::regex_filter::{min_evidence, prune_analyzer};


#[inline]
pub fn build_lower_hit_index(hits: &FxHashSet<&str>) -> FxHashSet<String> {
    let mut out = FxHashSet::with_capacity_and_hasher(hits.len(), Default::default());
    for &h in hits {
        out.insert(h.to_ascii_lowercase());
    }
    out
}
