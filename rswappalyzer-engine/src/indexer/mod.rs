mod enums;
pub mod matcher;
mod index_rules;
mod compiled;
mod library;
mod builder;

// 对外只导出具体内容，不导出模块名
pub use enums::{MatchGate, StructuralPrereq, MatcherSpec};
pub use matcher::Matcher;
pub use index_rules::{CommonIndexedRule, ScopedIndexedRule, RawMatchSet, PatternList, PatternMap};
pub use compiled::{CompiledPattern, CompiledTechRule, ExecutablePattern};
pub use library::{CompiledRuleLibrary, RuleLibraryIndex};
pub use builder::RuleIndexer;