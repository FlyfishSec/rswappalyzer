//! ID补全模块：仅负责将「字符串版CompiledPattern」补全为带ID的版本
//! 核心：只处理ID转换，不关心Pattern的编译逻辑

use crate::{
    CompiledPattern, CompiledTechRule, MatchGate, compiled::{LiteralInterner}
};
use rustc_hash::{FxHashMap};

/// ID补全器（仅处理ID转换）
#[derive(Debug, Clone, Default)]
pub struct IdFiller;

impl IdFiller {
    /// 补全所有技术规则的ID
    pub fn fill_all_tech_ids(
        mut tech_rules: FxHashMap<String, CompiledTechRule>,
        literal_interner: &LiteralInterner,
    ) -> FxHashMap<String, CompiledTechRule> {
        for (_, tech) in &mut tech_rules {
            Self::fill_content_patterns_ids(&mut tech.url_patterns, literal_interner);
            Self::fill_content_patterns_ids(&mut tech.html_patterns, literal_interner);
            Self::fill_content_patterns_ids(&mut tech.script_patterns, literal_interner);
            
            Self::fill_keyed_patterns_ids(&mut tech.meta_patterns, literal_interner);
            Self::fill_keyed_patterns_ids(&mut tech.header_patterns, literal_interner);
            Self::fill_keyed_patterns_ids(&mut tech.cookie_patterns, literal_interner);
        }
        tech_rules
    }

    /// 补全普通内容Pattern的ID
    fn fill_content_patterns_ids(
        patterns: &mut Option<Vec<CompiledPattern>>,
        literal_interner: &LiteralInterner,
    ) {
        if let Some(pats) = patterns {
            for pat in pats {
                Self::fill_single_pattern_id(pat, literal_interner);
            }
        }
    }

    /// 补全带Key的Pattern的ID
    fn fill_keyed_patterns_ids(
        patterns: &mut Option<FxHashMap<String, Vec<CompiledPattern>>>,
        literal_interner: &LiteralInterner,
    ) {
        if let Some(pats_map) = patterns {
            for (_, pats) in pats_map {
                for pat in pats {
                    Self::fill_single_pattern_id(pat, literal_interner);
                }
            }
        }
    }

    /// 补全单个Pattern的ID
    fn fill_single_pattern_id(
        pattern: &mut CompiledPattern,
        literal_interner: &LiteralInterner,
    ) {
        // 1. 重新生成带ID的MatchGate
        pattern.exec.match_gate = MatchGate::fill_ids(
            pattern.exec.match_gate.clone(),
            literal_interner,
        );
    }
}
