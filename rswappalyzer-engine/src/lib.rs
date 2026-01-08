//! 技术规则匹配引擎 - 标准化规则解析/编译/索引/匹配/清洗
//#![warn(missing_docs)]        // 强制要求文档注释，提升代码规范性
#![forbid(unsafe_code)]      // 禁止unsafe代码，最大化内存安全
#![warn(unused_imports)]     // 警告未使用的导入，清理冗余代码
#![warn(unused_variables)]   // 警告未使用的变量，减少内存浪费

/// 编译特性开关
#[cfg(feature = "full-meta")]
pub const FULL_META_ENABLED: bool = true;

/// 是否启用了 `full-meta` 编译特性（未开启时）
#[cfg(not(feature = "full-meta"))]
pub const FULL_META_ENABLED: bool = false;

/// 核心公共结构体+枚举
pub mod core;
/// 规则索引构建+编译核心逻辑
pub mod indexer;
/// 规则清洗+处理+索引构建
pub mod processor;
/// 剪枝工具
pub mod pruner;
/// 规则源解析 (Wappalyzer JSON)
pub mod source;
/// 正则过滤+剪枝策略+最小证据集
pub mod regex_filter;
/// 规则清洗子模块
pub mod cleaner;
/// 自定义错误
pub mod error;
// 通用工具函数
pub mod utils;

// 导出业务层顶层结构体/枚举/单例
pub use core::*;
pub use indexer::*;
pub use processor::*;
pub use pruner::*;
pub use utils::*;
pub use error::*;
