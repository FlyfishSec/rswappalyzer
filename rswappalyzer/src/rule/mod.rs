//! 规则模块：负责规则的加载、缓存、数据模型定义与预处理
pub mod cache;
pub mod loader;

// 统一导出核心公共接口
pub use cache::rule_cache::RuleCacheManager;
pub use loader::rule_loader::RuleLoader;
