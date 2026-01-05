//! 规则源解析模块
//! 统一导出通用解析器 Trait 和各源解析器

pub mod base_parser;
pub mod fingerprinthub;
pub mod wappalyzer_go;

// 通用解析器导出
pub use base_parser::{RuleSourceParser, ErasedRuleSourceParser, RuleFileType};
// FH 解析器导出
pub use crate::rule::source::fingerprinthub::parser::FingerprintHubParser;
// Wappalyzer 解析器导出
pub use crate::rule::source::wappalyzer_go::parser::WappalyzerGoParser;