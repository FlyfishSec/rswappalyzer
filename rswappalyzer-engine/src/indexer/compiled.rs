use std::borrow::Cow;

use crate::{
    Matcher, indexer::{MatcherSpec, enums::MatchGate}, preview::preview_compact, pruner::{min_evidence_checker, scope_pruner}, scope_pruner::PruneScope
};
use once_cell::sync::OnceCell;
use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};

/// 可执行匹配模式（核心执行单元）
/// 职责：封装「如何匹配」的完整逻辑，包含匹配执行体、准入网关、权重和版本模板
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutablePattern {
    /// 匹配器静态描述（用于序列化）
    pub matcher: MatcherSpec,
    /// 懒加载的Matcher缓存（运行时使用，不序列化）
    #[serde(skip)]
    #[serde(default)]
    pub matcher_cache: OnceCell<Matcher>,

    /// 匹配准入网关（剪枝规则）
    #[serde(default)]
    pub match_gate: MatchGate,
    /// 匹配置信度（0-100）
    pub confidence: u8,
    /// 版本提取模板（可选）
    pub version_template: Option<String>,
}

impl ExecutablePattern {
    /// 懒加载获取Matcher实例（OnceCell确保只初始化一次）
    #[inline(always)]
    pub fn get_matcher(&self) -> &Matcher {
        self.matcher_cache.get_or_init(|| self.matcher.to_matcher())
    }
}

/// 编译后的匹配模式（调度路由单元）
/// 职责：封装调度作用域、索引Key和可执行匹配核心，实现高性能匹配调度
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledPattern {
    /// 剪枝作用域（URL/HTML/Script等）
    pub scope: PruneScope,
    /// 索引Key（用于快速查找）
    #[serde(default)]
    pub index_key: String,
    /// 可执行匹配核心
    pub exec: ExecutablePattern,
}

impl CompiledPattern {
    /// 执行匹配（自动激活懒加载Matcher）
    /// 参数：input - 待匹配的字符串
    /// 返回：匹配结果（bool）
    #[inline(always)]
    pub fn matches(&self, input: &str) -> bool {
        self.exec.get_matcher().matches(input)
    }

    /// 剪枝过滤（纯业务逻辑，无日志，极致性能）
    /// 优先级：全局黑名单剪枝 > MatchGate统一剪枝
    /// 参数：
    /// - input: 待匹配字符串
    /// - input_tokens: 输入令牌集合（用于最小证据校验）
    /// 返回：是否通过剪枝（true=继续匹配，false=直接过滤）
    #[inline(always)]
    pub fn prune_check(&self, input: &str, input_tokens: &FxHashSet<String>) -> bool {
        // 优先级1: 全局黑名单剪枝
        scope_pruner::struct_prune(self.scope, input, Some(&self.index_key))
        // 优先级2: MatchGate统一剪枝（收敛min_evidence + prune_strategy）
        && self.exec.match_gate.check(input, input_tokens)
    }

    /// 剪枝 + 匹配 核心方法（高性能）
    /// 参数：
    /// - input: 待匹配字符串
    /// - input_tokens: 输入令牌集合
    /// 返回：是否通过剪枝且匹配成功
    #[inline(always)]
    pub fn matches_with_prune(&self, input: &str, input_tokens: &FxHashSet<String>) -> bool {
        self.prune_check(input, input_tokens) && self.matches(input)
    }

    /// 剪枝 + 匹配（带完整调试日志）
    /// 参数：
    /// - input: 待匹配字符串
    /// - input_tokens: 输入令牌集合
    /// 返回：是否通过剪枝且匹配成功
    #[inline(always)]
    pub fn matches_with_prune_log(&self, input: &str, input_tokens: &FxHashSet<String>) -> bool {
        self.prune_check_with_log(input, input_tokens) && self.matches(input)
    }

    /// 剪枝过滤（带完整调试日志）
    /// 参数：
    /// - input: 待匹配字符串
    /// - input_tokens: 输入令牌集合
    /// 返回：是否通过剪枝
    #[inline(always)]
    pub fn prune_check_with_log(&self, input: &str, input_tokens: &FxHashSet<String>) -> bool {
        let input_preview = preview_compact(input, 120);
        let matcher_desc = self.exec.get_matcher().describe();

        // 1. 全局黑名单剪枝校验
        if !scope_pruner::struct_prune(self.scope, input, Some(&self.index_key)) {
            log::debug!(
                "Blacklist prune filtered | Scope: {:?} | Input preview: {} | Length: {} | Rule: {}",
                self.scope,
                input_preview,
                input.len(),
                matcher_desc
            );
            return false;
        }

        // 2. MatchGate各类型剪枝校验
        match &self.exec.match_gate {
            MatchGate::Open => {
                log::debug!(
                    "Prune allowed (fallback) | Reason: MatchGate is Open (no check) | Input preview: {} | Rule: {}",
                    input_preview,
                    matcher_desc
                );
            }
            MatchGate::RequireAll(set) => {
                let (pass_evidence, missing_evidence) =
                    min_evidence_checker::check_min_evidence_prune_with_missing(set, input_tokens);
                
                if !pass_evidence {
                    log::debug!(
                        "Min evidence prune filtered | Input preview: {} | Evidence set: {:?} | Missing evidence: {:?} | Input tokens: {:?} | Rule: {}",
                        input_preview,
                        set,
                        missing_evidence,
                        input_tokens,
                        matcher_desc
                    );
                    return false;
                } else {
                    log::debug!(
                        "Min evidence prune allowed | Reason: {} | Input preview: {} | Evidence set: {:?} | Rule: {}",
                        if set.is_empty() {
                            "Empty evidence set (fallback allow)"
                        } else {
                            "Token intersection matched"
                        },
                        input_preview,
                        set,
                        matcher_desc
                    );
                }
            }
            MatchGate::RequireAnyLiteral(list) => {
                let hit = list.iter().any(|substr| input.contains(substr));
                if !hit {
                    log::debug!(
                        "Structural prereq prune filtered | Input preview: {} | Prereq (any match): {:?} | Rule: {}",
                        input_preview,
                        list,
                        matcher_desc
                    );
                    return false;
                }
                log::debug!(
                    "Structural prereq prune allowed | Prereq (any match): {:?} | Input preview: {} | Rule: {}",
                    list,
                    input_preview,
                    matcher_desc
                );
            }
        }

        true
    }

    /// 日志内容压缩（智能无拷贝）
    /// 特性：
    /// 1. 短字符串（≤max_len）：返回Borrowed（零拷贝）
    /// 2. 长字符串：截断并替换空格为单空格，添加省略号
    /// 参数：
    /// - input: 原始字符串
    /// - max_len: 最大长度
    /// 返回：压缩后的字符串（Cow智能指针）
    #[allow(dead_code)]
    fn compress_for_log(input: &str, max_len: usize) -> Cow<'_, str> {
        if input.len() <= max_len {
            return Cow::Borrowed(input);
        }

        let mut compressed = String::with_capacity(max_len + 1);
        let mut last_was_whitespace = false;

        for ch in input.chars() {
            if ch.is_whitespace() {
                if !last_was_whitespace {
                    compressed.push(' ');
                    last_was_whitespace = true;
                }
            } else {
                compressed.push(ch);
                last_was_whitespace = false;
            }

            if compressed.len() >= max_len {
                compressed.push('…');
                break;
            }
        }

        Cow::Owned(compressed)
    }
}

/// 编译后技术规则（完整技术匹配规则）
/// 职责：封装单个技术的所有匹配模式，按作用域分类存储
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledTechRule {
    /// 技术名称
    pub name: String,
    /// URL匹配模式列表（可选）
    pub url_patterns: Option<Vec<CompiledPattern>>,
    /// HTML匹配模式列表（可选）
    pub html_patterns: Option<Vec<CompiledPattern>>,
    /// Script匹配模式列表（可选）
    pub script_patterns: Option<Vec<CompiledPattern>>,
    /// Meta匹配模式映射（Key=Meta名称，Value=匹配模式列表）
    pub meta_patterns: Option<FxHashMap<String, Vec<CompiledPattern>>>,
    /// Header匹配模式映射（Key=Header名称，Value=匹配模式列表）
    pub header_patterns: Option<FxHashMap<String, Vec<CompiledPattern>>>,
    /// Cookie匹配模式映射（Key=Cookie名称，Value=匹配模式列表）
    pub cookie_patterns: Option<FxHashMap<String, Vec<CompiledPattern>>>,
    /// 所属分类ID列表
    pub category_ids: Vec<u32>,
    /// 推导技术列表（匹配该技术后可推导的其他技术）
    pub implies: Vec<String>,
}