//! 规则加载模块
//! 统一导出规则加载相关组件
pub mod rule_loader;
pub mod path_manager;
pub mod etag_manager;
pub mod etag;
pub mod remote_fetcher;
pub mod rule_processor;
pub mod remote_source;

// 导出 ETag 相关
pub use etag::{ETagRecord, ETagTotalRecord};
// 导出远程源相关
//pub use remote_source::{RemoteRuleSource, FetchMode, RuleFileType};
pub use remote_source::{RemoteRuleSource, FetchMode};

// 导出加载器
pub use rule_loader::RuleLoader;
pub use path_manager::RulePathManager;
pub use etag_manager::EtagManager;
pub use remote_fetcher::RemoteRuleFetcher;
pub use rule_processor::RuleProcessor;