//! 通用远程规则源配置
//! 定义统一的远程源结构，不耦合具体解析器

use std::fmt;
use crate::RuleSourceParser;

// 注意：这里导入的是 ErasedRuleSourceParser，不是 RuleSourceParser
use super::super::source::{RuleFileType, ErasedRuleSourceParser};

/// 拉取模式枚举
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchMode {
    Override, // 优先级覆盖模式（取第一个有效源）
    Merge,    // 多源合并模式（合并所有有效源规则）
}

impl fmt::Display for FetchMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchMode::Override => write!(f, "Override"),
            FetchMode::Merge => write!(f, "Merge"),
        }
    }
}

/// 通用远程规则源配置
#[derive(Debug, Clone)]
pub struct RemoteRuleSource {
    pub name: String,                           // 源名称
    pub raw_url: String,                        // 原始 URL
    pub rule_file_type: RuleFileType,           // 规则文件类型
    // 修正：使用无泛型的 ErasedRuleSourceParser，不再使用 Arc<dyn RuleSourceParser>
    pub parser: ErasedRuleSourceParser,
}

impl RemoteRuleSource {
    /// 创建远程规则源（简化构造）
    pub fn new<O, P>(name: &str, raw_url: &str, parser: P) -> Self
    where
        // 约束 O：原始规则类型需满足的条件
        O: serde::de::DeserializeOwned + Send + Sync + 'static,
        // 约束 P：具体解析器需实现带泛型 O 的 RuleSourceParser，且满足线程安全和 Any 特质
        P: RuleSourceParser<O> + std::any::Any + Send + Sync + 'static,
    {
        // 先将具体解析器封装为无泛型的 ErasedRuleSourceParser
        let erased_parser = ErasedRuleSourceParser::new(parser);
        Self {
            name: name.to_string(),
            raw_url: raw_url.to_string(),
            // 从封装后的解析器中获取规则文件类型
            rule_file_type: erased_parser.rule_file_type(),
            parser: erased_parser,
        }
    }
}