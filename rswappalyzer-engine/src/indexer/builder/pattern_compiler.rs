//! 规则编译模块：仅负责将原始规则编译为「字符串版CompiledPattern」
//! 核心：不处理任何ID转换，只关注规则→Matcher→MatchGate的String转换

use crate::{
    builder::evidence::{extract_any_literals, extract_min_evidence_literal},
    compiled::{LiteralInterner, PatternEvidence},
    matcher::fold_to_match_gate,
    CommonIndexedRule, CompiledPattern, EvidenceKind, ExecutablePattern, MatchType, MatcherSpec,
    Scope,
};
use rustc_hash::FxHashMap;

/// 规则编译器
#[derive(Debug, Clone, Default)]
pub struct PatternCompiler;

impl PatternCompiler {
    /// 编译普通内容规则（Url/Html/Script）
    pub fn compile_content_patterns(
        rules: &[CommonIndexedRule],
        scope: Scope,
        literal_interner: &mut LiteralInterner,
    ) -> Option<Vec<CompiledPattern>> {
        let mut pats = Vec::new();

        for r in rules {
            // 为Contains创建LiteralId
            let literal_id = if r.match_type == MatchType::Contains {
                Some(literal_interner.get_or_insert(&r.pattern.pattern))
            } else {
                None
            };

            // // 构建PatternEvidence（分字段存储不同类型字面量）
            // let evidence = Self::build_pattern_evidence(r);
            // //let literal_type = Self::get_literal_type(&evidence);

            // 构建PatternEvidence（分字段存储不同类型字面量）
            let evidence = Self::build_pattern_evidence(r);

            // 构建MatcherSpec
            let matcher_spec = match r.match_type {
                MatchType::Contains => MatcherSpec::Contains(literal_id.unwrap()),
                MatchType::Exists => MatcherSpec::Exists,
                MatchType::Regex => MatcherSpec::Regex {
                    pattern: r.pattern.pattern.clone(),
                    case_insensitive: true,
                },
            };

            // 提取结构前置条件
            //let structural_prereq = StructuralPrereq::from_matcher(&matcher, literal_interner);

            // 判定证据类型(剪枝作用域)
            //let evidence_kind = Self::judge_evidence_kind(&matcher, &evidence);
            let evidence_kind = Self::judge_evidence_kind(&matcher_spec, &evidence);

            // 生成无ID的MatchGate
            let match_gate = fold_to_match_gate(&evidence);

            pats.push(CompiledPattern {
                scope: scope.into(),
                index_key: String::new(),
                literal_id,
                evidence_kind,
                evidence,
                exec: ExecutablePattern {
                    //matcher: matcher.to_spec(),
                    matcher: matcher_spec,
                    matcher_cache: once_cell::sync::OnceCell::new(),
                    //regex_cache: once_cell::sync::OnceCell::new(),
                    match_gate,
                    confidence: r.pattern.confidence,
                    version_template: r.pattern.version_template.clone(),
                },
            });
        }

        (!pats.is_empty()).then_some(pats)
    }

    /// 编译带Key的规则（Meta/Header/Cookie）
    pub fn compile_keyed_patterns(
        rules: &FxHashMap<String, Vec<CommonIndexedRule>>,
        scope: Scope,
        literal_interner: &mut LiteralInterner,
    ) -> Option<FxHashMap<String, Vec<CompiledPattern>>> {
        let mut pats = FxHashMap::default();

        for (k, rs) in rules {
            let mut rule_pats = Vec::new();

            for r in rs {
                let literal_id = if r.match_type == MatchType::Contains {
                    Some(literal_interner.get_or_insert(&r.pattern.pattern))
                } else {
                    None
                };

                // 构建PatternEvidence（分字段存储不同类型字面量）
                let evidence = Self::build_pattern_evidence(r);
                //let literal_type = Self::get_literal_type(&evidence);

                let matcher_spec = match r.match_type {
                    MatchType::Contains => MatcherSpec::Contains(literal_id.unwrap()),
                    MatchType::Exists => MatcherSpec::Exists,
                    MatchType::Regex => MatcherSpec::Regex {
                        pattern: r.pattern.pattern.clone(),
                        case_insensitive: true,
                    },
                };

                // 构建剪枝门控
                //let structural_prereq = StructuralPrereq::from_matcher(&matcher, literal_interner);
                let evidence_kind = Self::judge_evidence_kind(&matcher_spec, &evidence);
                let match_gate = fold_to_match_gate(&evidence);

                rule_pats.push(CompiledPattern {
                    scope: scope.into(),
                    index_key: k.clone(),
                    literal_id,
                    evidence_kind,
                    evidence,
                    exec: ExecutablePattern {
                        matcher: matcher_spec,
                        matcher_cache: once_cell::sync::OnceCell::new(),
                        //regex_cache: once_cell::sync::OnceCell::new(),
                        match_gate,
                        confidence: r.pattern.confidence,
                        version_template: r.pattern.version_template.clone(),
                    },
                });
            }

            if !rule_pats.is_empty() {
                pats.insert(k.to_ascii_lowercase(), rule_pats);
            }
        }

        (!pats.is_empty()).then_some(pats)
    }

    /// 判定证据类型（LiteralBased/NoLiteral/ExistsOnly）
    fn judge_evidence_kind(matcher: &MatcherSpec, evidence: &PatternEvidence) -> EvidenceKind {
        match matcher {
            MatcherSpec::Exists => EvidenceKind::ExistsOnly,
            MatcherSpec::Contains(_) => EvidenceKind::LiteralBased,
            MatcherSpec::Regex { .. } => {
                // 使用已提取的 literals 判断
                if !evidence.literals.is_empty() {
                    EvidenceKind::LiteralBased
                } else {
                    EvidenceKind::NoLiteral
                }
            }
        }
    }

    /// 根据MatchType构建PatternEvidence
    fn build_pattern_evidence(r: &CommonIndexedRule) -> PatternEvidence {
        let pattern_str: &str = &r.pattern.pattern;

        match r.match_type {
            MatchType::Contains => PatternEvidence {
                literals: vec![pattern_str.to_owned()],
                contains: pattern_str.to_owned(),
                any_literals: vec![pattern_str.to_owned()],
            },

            MatchType::Regex => PatternEvidence {
                literals: extract_min_evidence_literal(pattern_str)
                    .into_iter()
                    .collect(),
                contains: String::new(),
                any_literals: extract_any_literals(pattern_str),
            },

            MatchType::Exists => PatternEvidence {
                literals: Vec::new(),
                contains: String::new(),
                any_literals: Vec::new(),
            },
        }
    }

    // 映射LiteralType
    // fn get_literal_type(evidence: &PatternEvidence) -> LiteralType {
    //     if evidence.literals.is_empty() {
    //         LiteralType::Literal
    //     } else if !evidence.contains.is_empty() {
    //         LiteralType::Contains
    //     } else if !evidence.any_literals.is_empty() {
    //         LiteralType::AnyLiteral
    //     } else {
    //         // Exists / PureRegex 兜底
    //         LiteralType::AnyLiteral
    //     }
    // }

    // /// 提取最小证据元数据（仅字符串）
    // pub fn extract_min_evidence_with_meta(
    //     matcher: &Matcher,
    //     literal_interner: &LiteralInterner,
    // ) -> MinEvidenceMeta {
    //     match matcher {
    //         Matcher::Contains(lid) => {
    //             let literal_str = literal_interner.get_literal(*lid).unwrap_or("");
    //             let literal = literal_str.to_ascii_lowercase();
    //             let source_len = literal.len();
    //             let tokens = if literal.len() > 2 {
    //                 crate::pruner::tokenizer::extract_atomic_tokens(&literal)
    //             } else {
    //                 FxHashSet::default()
    //             };
    //             MinEvidenceMeta {
    //                 tokens,
    //                 source_len,
    //                 source_literal: literal,
    //             }
    //         }
    //         Matcher::LazyRegex { pattern, .. } => {
    //             let min_evidence =
    //                 crate::pruner::min_evidence::extract_min_evidence_meta(pattern.as_str());
    //             MinEvidenceMeta {
    //                 tokens: min_evidence.tokens,
    //                 source_len: min_evidence.source_len,
    //                 source_literal: min_evidence.source_literal,
    //             }
    //         }
    //         Matcher::Exists => MinEvidenceMeta {
    //             tokens: FxHashSet::default(),
    //             source_len: 0,
    //             source_literal: String::new(),
    //         },
    //     }
    // }
}
