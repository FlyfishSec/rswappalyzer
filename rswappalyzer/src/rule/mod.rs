//! 规则模块：负责规则的加载、缓存、数据模型定义与预处理
pub mod core;
pub mod source;
pub mod cache;
pub mod loader;
pub mod cleaner;
pub mod indexer;
pub mod transformer;
//pub mod compiler;
//pub mod converter;


// 统一导出核心公共接口
pub use core::{
    DetectResult, CategoryRule, RuleLibrary,
    MatchCondition
};

pub use cache::rule_cache::RuleCacheManager;
pub use loader::rule_loader::RuleLoader;
pub use loader::remote_source::{RemoteRuleSource};
pub use crate::rule::source::RuleFileType;
pub use cleaner::rule_cleaner::RuleCleaner;