//! 无证据规则索引构建器
//! 职责：仅处理无证据规则的判定和索引构建

use crate::{
    compiled::{TechId, TechInterner},
    CompiledPattern, CompiledTechRule, Scope,
};
use rustc_hash::{FxHashMap, FxHashSet};

/// 无证据索引构建结果
#[derive(Debug, Clone, Default)]
pub struct NoEvidenceIndexBuildResult {
    /// 无证据规则索引（Scope -> TechId集合）
    pub no_evidence_index: FxHashMap<Scope, FxHashSet<TechId>>,
}

/// 无证据索引构建器（职责单一）
#[derive(Debug, Clone, Copy, Default)]
pub struct NoEvidenceIndexBuilder;

impl NoEvidenceIndexBuilder {
    /// 构建无证据规则索引
    /// 注意：需在 Literal/Any/Contains 索引构建完成后调用
    pub fn build(
        compiled_tech: &FxHashMap<String, CompiledTechRule>,
        tech_interner: &mut TechInterner,
    ) -> NoEvidenceIndexBuildResult {
        let mut no_evidence_index = FxHashMap::default();

        // 遍历所有技术规则，填充无证据索引
        for (tech_name, tech_rule) in compiled_tech {
            let tech_id = tech_interner.get_or_insert(tech_name);
            Self::process_no_evidence_patterns(tech_id, tech_rule, &mut no_evidence_index);
        }

        NoEvidenceIndexBuildResult { no_evidence_index }
    }

    /// 处理无证据规则，填充无证据索引
    fn process_no_evidence_patterns(
        tech_id: TechId,
        rule: &CompiledTechRule,
        no_evidence_map: &mut FxHashMap<Scope, FxHashSet<TechId>>,
    ) {
        // 处理内容型无证据规则（Url/Html/Script）
        Self::insert_no_evidence_if_needed(
            tech_id,
            rule.url_patterns.as_ref(),
            Scope::Url,
            no_evidence_map,
        );
        Self::insert_no_evidence_if_needed(
            tech_id,
            rule.html_patterns.as_ref(),
            Scope::Html,
            no_evidence_map,
        );
        Self::insert_no_evidence_if_needed(
            tech_id,
            rule.script_patterns.as_ref(),
            Scope::Script,
            no_evidence_map,
        );

        // 处理KV型无证据规则（Meta/Header/Cookie）
        Self::insert_no_evidence_nested_if_needed(
            tech_id,
            rule.meta_patterns.as_ref(),
            Scope::Meta,
            no_evidence_map,
        );
        Self::insert_no_evidence_nested_if_needed(
            tech_id,
            rule.header_patterns.as_ref(),
            Scope::Header,
            no_evidence_map,
        );
        Self::insert_no_evidence_nested_if_needed(
            tech_id,
            rule.cookie_patterns.as_ref(),
            Scope::Cookie,
            no_evidence_map,
        );
    }

    /// 判断内容型规则是否为无证据规则，若是则插入索引
    fn insert_no_evidence_if_needed<T: AsRef<[CompiledPattern]>>(
        tech_id: TechId,
        patterns: Option<&T>,
        scope: Scope,
        no_evidence_map: &mut FxHashMap<Scope, FxHashSet<TechId>>,
    ) {
        if Self::has_no_evidence(patterns) {
            no_evidence_map.entry(scope).or_default().insert(tech_id);
        }
    }

    /// 判断KV型规则是否为无证据规则，若是则插入索引
    fn insert_no_evidence_nested_if_needed<K, V>(
        tech_id: TechId,
        patterns: Option<&FxHashMap<K, V>>,
        scope: Scope,
        no_evidence_map: &mut FxHashMap<Scope, FxHashSet<TechId>>,
    ) where
        V: AsRef<[CompiledPattern]>,
    {
        if Self::has_no_evidence_nested(patterns) {
            no_evidence_map.entry(scope).or_default().insert(tech_id);
        }
    }

    /// 无证据规则判定逻辑
    /// 判定标准：PatternEvidence下的literal/contains/any_literals全部无有效内容
    fn has_no_evidence<T: AsRef<[CompiledPattern]>>(patterns: Option<&T>) -> bool {
        patterns.map_or(false, |p| {
            p.as_ref()
                .iter()
                .any(|cp| {
                    // 1. literal 为 None
                    let literal_empty = cp.evidence.literals.is_empty();
                    // 2. contains 为空字符串（去除空白字符）
                    let contains_empty = cp.evidence.contains.trim().is_empty();
                    // 3. any_literals 为空Vec
                    let any_literals_empty = cp.evidence.any_literals.is_empty();
                    
                    // 三个条件同时满足 = 无证据
                    literal_empty && contains_empty && any_literals_empty
                })
        })
    }

    /// 嵌套KV型规则的无证据判定
    fn has_no_evidence_nested<K, V>(patterns: Option<&FxHashMap<K, V>>) -> bool
    where
        V: AsRef<[CompiledPattern]>,
    {
        patterns.map_or(false, |map| {
            map.values().any(|p| Self::has_no_evidence(Some(p)))
        })
    }
}