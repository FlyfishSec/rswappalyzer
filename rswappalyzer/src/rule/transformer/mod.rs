//! 规则标准化转换器
//! 统一将不同源的原始规则转换为标准 RuleLibrary
use crate::error::{RswResult};
use crate::rule::core::RuleLibrary;

/// 规则转换特质
pub trait RuleTransformer {
    /// 将原始规则转换为标准 RuleLibrary
    fn transform(&self) -> RswResult<RuleLibrary>;
}

pub mod wappalyzer_transformer;
pub mod wappalyzer_common;
pub use wappalyzer_transformer::WappalyzerGoTransformer;