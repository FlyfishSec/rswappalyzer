use aho_corasick::{AhoCorasick, AhoCorasickBuilder, BuildError, MatchKind};
use rustc_hash::FxHashSet;
use crate::{CompiledRuleLibrary, PruneScope};

/// 全局AC自动机缓存实例
/// 按扫描维度拆分HTML/Header专用自动机，仅初始化一次
#[derive(Debug, Clone)]
pub struct AcAutomatonCache {
    /// HTML维度专用字面量匹配自动机（覆盖html/meta/script scope）
    pub html_literal_ac: AhoCorasick,
    /// HTML维度专用任意字面量匹配自动机
    pub html_any_ac: AhoCorasick,
    /// Header维度专用字面量匹配自动机（覆盖header/cookie scope）
    pub header_literal_ac: AhoCorasick,
    /// Header维度专用任意字面量匹配自动机
    pub header_any_ac: AhoCorasick,
}

impl AcAutomatonCache {
    /// 从编译规则库构建全局AC自动机缓存
    /// 参数:
    /// - compiled_lib: 预编译的规则库实例
    /// 返回: 缓存实例 | 构建错误
    pub fn new(compiled_lib: &CompiledRuleLibrary) -> Result<Self, BuildError> {
        // 聚合HTML维度所有scope的字面量
        let mut html_literals = FxHashSet::default();
        for scope in [PruneScope::Html, PruneScope::Meta, PruneScope::Script] {
            if let Some(scope_literals) = compiled_lib.known_literals_by_scope.get(&scope) {
                html_literals.extend(scope_literals.iter().cloned());
            }
        }
        let html_literals_vec: Vec<String> = html_literals.into_iter().collect();

        // 聚合HTML维度所有scope的任意字面量
        let mut html_any_literals = FxHashSet::default();
        for scope in [PruneScope::Html, PruneScope::Meta, PruneScope::Script] {
            if let Some(scope_any) = compiled_lib.known_any_by_scope.get(&scope) {
                html_any_literals.extend(scope_any.iter().cloned());
            }
        }
        let html_any_vec: Vec<String> = html_any_literals.into_iter().collect();

        // 构建HTML维度AC自动机
        let html_literal_ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostLongest)
            .build(&html_literals_vec)?;
        
        let html_any_ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostLongest)
            .build(&html_any_vec)?;

        // 聚合Header维度所有scope的字面量
        let mut header_literals = FxHashSet::default();
        for scope in [PruneScope::Header, PruneScope::Cookie] {
            if let Some(scope_literals) = compiled_lib.known_literals_by_scope.get(&scope) {
                header_literals.extend(scope_literals.iter().cloned());
            }
        }
        let header_literals_vec: Vec<String> = header_literals.into_iter().collect();

        // 聚合Header维度所有scope的任意字面量
        let mut header_any_literals = FxHashSet::default();
        for scope in [PruneScope::Header, PruneScope::Cookie] {
            if let Some(scope_any) = compiled_lib.known_any_by_scope.get(&scope) {
                header_any_literals.extend(scope_any.iter().cloned());
            }
        }
        let header_any_vec: Vec<String> = header_any_literals.into_iter().collect();

        // 构建Header维度AC自动机
        let header_literal_ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostLongest)
            .build(&header_literals_vec)?;
        
        let header_any_ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostLongest)
            .build(&header_any_vec)?;

        Ok(Self {
            html_literal_ac,
            html_any_ac,
            header_literal_ac,
            header_any_ac,
        })
    }
}