//! 规则模型模块
//! 统一导出通用模型和各源专属模型

pub mod base;
pub mod parsed_rule;
pub mod pattern;
pub mod pattern_list;
pub mod category_rule;
pub mod detect_result;


// 通用模型导出
pub use base::{RuleLibrary, CachedTechRule, TechBasicInfo, MatchCondition};
// 分类规则导出
pub use category_rule::{CategoryRule, get_default_categories};

// 标记模式导出
pub use parsed_rule::{ParsedTechRule, TechMatcher};
pub use pattern_list::{PatternList, PatternMap};
pub use pattern::{MatchType, Pattern};
// 技术规则/检测结果导出
pub use detect_result::DetectResult;
