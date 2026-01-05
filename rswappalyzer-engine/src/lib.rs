// 核心公共结构体+枚举
pub mod core;
// 规则索引构建+编译核心逻辑
pub mod indexer;
// 规则清洗+处理+索引构建
pub mod processor;
// 规则源解析 (Wappalyzer JSON)
pub mod source;
// 正则过滤+剪枝策略+最小证据集
pub mod regex_filter;
// 规则清洗子模块
pub mod cleaner;

// 顶层导出常用类型
pub use core::{
    CategoryRule, KeyedPattern, MatchCondition, MatchRuleSet, MatchScope, MatchType,
    ParsedTechRule, Pattern, RuleLibrary, TechBasicInfo,
};
pub use indexer::{
    CompiledPattern, CompiledRuleLibrary, CompiledTechRule, CommonIndexedRule, Matcher,
    PruneScope, PruneStrategy, RawMatchSet, RuleIndexer, RuleLibraryIndex, ScopedIndexedRule,
};
pub use processor::RuleProcessor;