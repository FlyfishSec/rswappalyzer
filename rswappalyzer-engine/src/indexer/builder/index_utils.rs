use crate::{
    CompiledPattern, CompiledTechRule, Scope,
    compiled::{LiteralId, LiteralInterner, PatternEvidence, TechId},
};
use rustc_hash::{FxHashMap, FxHashSet};

// ========== 核心抽象层 ==========

/// 定义模式遍历器的Trait，统一不同数据源的遍历方式
pub trait PatternIterator {
    /// 遍历所有CompiledPattern
    fn for_each_pattern<F: FnMut(&CompiledPattern)>(self, f: F);
}

// 为Option<&Vec<CompiledPattern>>实现PatternIterator
impl PatternIterator for Option<&Vec<CompiledPattern>> {
    fn for_each_pattern<F: FnMut(&CompiledPattern)>(self, mut f: F) {
        if let Some(pats) = self {
            for pat in pats {
                f(pat);
            }
        }
    }
}

// 为Option<&FxHashMap<String, Vec<CompiledPattern>>>实现PatternIterator
impl PatternIterator for Option<&FxHashMap<String, Vec<CompiledPattern>>> {
    fn for_each_pattern<F: FnMut(&CompiledPattern)>(self, mut f: F) {
        if let Some(keyed_pats) = self {
            for (_key, pats) in keyed_pats {
                for pat in pats {
                    f(pat);
                }
            }
        }
    }
}

/// 处理单个字面量字符串的核心逻辑
fn process_single_literal(
    tech_id: TechId,
    literal_str: &str,
    scope: Scope,
    min_length: usize,
    literal_interner: &mut LiteralInterner,
    index: &mut FxHashMap<LiteralId, FxHashMap<Scope, FxHashSet<TechId>>>,
    known_literals: &mut FxHashSet<LiteralId>,
    known_by_scope: &mut FxHashMap<Scope, FxHashSet<LiteralId>>,
) {
    // 过滤短字符串
    if literal_str.len() < min_length {
        return;
    }
    
    // 转换为LiteralId
    let lit_id = literal_interner.get_or_insert(literal_str);
    
    // 更新索引
    update_index(
        tech_id,
        lit_id,
        scope,
        index,
        known_literals,
        known_by_scope,
    );
}

// ========== 公共工具函数 ==========

/// 公共的索引更新逻辑
pub fn update_index(
    tech_id: TechId,
    lit_id: LiteralId,
    scope: Scope,
    index: &mut FxHashMap<LiteralId, FxHashMap<Scope, FxHashSet<TechId>>>,
    known_literals: &mut FxHashSet<LiteralId>,
    known_by_scope: &mut FxHashMap<Scope, FxHashSet<LiteralId>>,
) {
    index
        .entry(lit_id)
        .or_default()
        .entry(scope)
        .or_default()
        .insert(tech_id);
    
    known_literals.insert(lit_id);
    known_by_scope
        .entry(scope)
        .or_default()
        .insert(lit_id);
}

/// 通用的模式处理函数
pub fn process_patterns<PI, F>(
    tech_id: TechId,
    patterns: PI,
    scope: Scope,
    literal_interner: &mut LiteralInterner,
    min_length: usize,
    index: &mut FxHashMap<LiteralId, FxHashMap<Scope, FxHashSet<TechId>>>,
    known_literals: &mut FxHashSet<LiteralId>,
    known_by_scope: &mut FxHashMap<Scope, FxHashSet<LiteralId>>,
    get_literals: F,
) where
    PI: PatternIterator,
    F: Fn(&PatternEvidence) -> Vec<&str>,
{
    patterns.for_each_pattern(|pat| {
        // 获取所有需要处理的字面量字符串
        let literals = get_literals(&pat.evidence);
        
        // 处理每个字面量
        for literal_str in literals {
            process_single_literal(
                tech_id,
                literal_str,
                scope,
                min_length,
                literal_interner,
                index,
                known_literals,
                known_by_scope,
            );
        }
    });
}

/// 辅助函数：适配单个可选字面量的场景
pub fn get_single_literal(f: impl Fn(&PatternEvidence) -> Option<&str>) -> impl Fn(&PatternEvidence) -> Vec<&str> {
    move |evidence| {
        f(evidence).map(|s| vec![s]).unwrap_or_default()
    }
}

/// 辅助函数：适配Vec<String>类型的字面量场景
pub fn get_vec_literals(f: impl Fn(&PatternEvidence) -> &Vec<String>) -> impl Fn(&PatternEvidence) -> Vec<&str> {
    move |evidence| {
        f(evidence).iter().map(|s| s.as_str()).collect()
    }
}

/// 最终化已知字面量
pub fn finalize_known_literals(
    known_literals: FxHashSet<LiteralId>,
    literal_interner: &LiteralInterner,
    min_length: usize,
) -> Vec<LiteralId> {
    known_literals
        .into_iter()
        .filter(|lit_id| {
            literal_interner
                .get_literal(*lit_id)
                .map_or(false, |s| s.len() >= min_length)
        })
        .collect()
}

// 公共Scope常量
pub const CONTENT_SCOPES: &[(&str, fn(&CompiledTechRule) -> Option<&Vec<CompiledPattern>>, Scope)] = &[
    ("url", |r| r.url_patterns.as_ref(), Scope::Url),
    ("html", |r| r.html_patterns.as_ref(), Scope::Html),
    ("script", |r| r.script_patterns.as_ref(), Scope::Script),
];

pub const KEYED_SCOPES: &[(&str, fn(&CompiledTechRule) -> Option<&FxHashMap<String, Vec<CompiledPattern>>>, Scope)] = &[
    ("meta", |r| r.meta_patterns.as_ref(), Scope::Meta),
    ("header", |r| r.header_patterns.as_ref(), Scope::Header),
    ("cookie", |r| r.cookie_patterns.as_ref(), Scope::Cookie),
];