//! 规则模块：负责规则的加载、缓存、数据模型定义
pub mod model;
pub mod source_eh;
pub mod cache;
pub mod loader;

// 导出核心接口
pub use self::model::{
    Technology, TechnologyLite, TechnologyLiteExt, serialize_tech_lite_list, TechRule, CategoryRule, RuleLibrary
};
pub use self::loader::RuleLoader;
pub use self::cache::RuleCacheManager;
//pub use self::source_eh::fetch_fallback_remote;