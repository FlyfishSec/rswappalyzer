//! Wappalyzer 规则转换器
//! 专门处理 Wappalyzer 原始规则到核心规则库的转换

use std::collections::HashMap;

use crate::error::{RswResult, RswappalyzerError};
use crate::rule::cleaner::pattern_processor::PatternProcessor;
use crate::rule::core::{RuleLibrary};
use crate::rule::source::wappalyzer_go::original::{WappalyzerOriginalRuleLibrary};

use super::{convert_wappalyzer_categories, convert_wappalyzer_tech_rule};

/// Wappalyzer 规则转换器
#[derive(Debug, Clone)]
pub struct WappalyzerConverter {
    original_library: WappalyzerOriginalRuleLibrary,
    pattern_processor: PatternProcessor,
}

impl WappalyzerConverter {
    /// 创建转换器实例
    pub fn new(original_library: WappalyzerOriginalRuleLibrary) -> Self {
        Self {
            original_library,
            pattern_processor: PatternProcessor::default(),
        }
    }

    /// 执行转换：原始规则 → 核心规则库
    pub fn convert(&self) -> RswResult<RuleLibrary> {
        let mut core_tech_map = HashMap::new();
        let mut category_rules = HashMap::new();

        // 1. 转换分类规则
        category_rules = convert_wappalyzer_categories(&self.original_library.categories);

        // 2. 转换技术规则
        for (tech_name, original_tech_rule) in &self.original_library.technologies {
            match convert_wappalyzer_tech_rule(tech_name, original_tech_rule, &self.pattern_processor) {
                Ok(parsed_rule) => {
                    core_tech_map.insert(tech_name.clone(), parsed_rule);
                }
                Err(e) => {
                    tracing::warn!("转换技术规则 [{}] 失败：{}，跳过该规则", tech_name, e);
                    continue;
                }
            }
        }

        // 3. 检查转换结果
        if core_tech_map.is_empty() {
            return Err(RswappalyzerError::RuleConvertError(
                "Wappalyzer 规则转换后无有效技术规则".to_string()
            ));
        }

        Ok(RuleLibrary {
            core_tech_map,
            category_rules,
        })
    }
}

/// 为 WappalyzerOriginalRuleLibrary 实现转换 trait
impl From<WappalyzerOriginalRuleLibrary> for WappalyzerConverter {
    fn from(original: WappalyzerOriginalRuleLibrary) -> Self {
        WappalyzerConverter::new(original)
    }
}