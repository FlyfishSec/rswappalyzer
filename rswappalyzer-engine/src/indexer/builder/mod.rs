//! 索引构建器子模块
//! 负责将不同类型的索引构建逻辑拆分到独立文件

pub mod any_index;
pub mod literal_index;
pub mod token_index;
pub mod rule_indexer;

// 导出统一的构建结果类型
// pub use any_index::AnyIndexBuildResult;
// pub use literal_index::LiteralIndexBuildResult;
// pub use token_index::TokenIndexBuildResult;