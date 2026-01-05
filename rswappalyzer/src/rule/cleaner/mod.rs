//! 规则清理模块
//! 负责过滤无效规则、修复正则表达式语法问题、预处理标记匹配类型，
//! 为后续规则匹配提供干净、可用的规则数据。

// 导出规则清理器结构体，供外部模块调用
pub mod rule_cleaner;
pub mod pattern_processor;
pub mod regex_fixer;
pub mod clean_stats;

pub use rule_cleaner::RuleCleaner;
pub use clean_stats::CleanStats;