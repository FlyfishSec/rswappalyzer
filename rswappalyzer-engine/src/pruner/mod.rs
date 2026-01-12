pub mod min_evidence;
pub mod min_evidence_checker;
pub mod tokenizer;
pub mod regex_literal;
pub mod scope_pruner;
pub mod prune_manager;
pub mod ac_manager;
pub mod input_evidence;

pub use scope_pruner::PruneScope;
pub use input_evidence::{header_evidence, html_evidence};