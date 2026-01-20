use log::{debug, warn};
use rswappalyzer_engine::{
    CompiledTechRule, MatcherSpec, RuleLibraryRuntime, Scope,
    compiled::{LiteralId, LiteralInterner}
};
// 统一使用 FxHashSet（适配项目实际的 FxBuildHasher）
use rustc_hash::FxHashSet;

/// 旁路调试函数：用于调试指定作用域下指定技术名的 LiteralHit 匹配情况
/// 
/// # 参数
/// - `scope`: 要调试的作用域（如 Scope::Script）
/// - `target_tech_name`: 要调试的目标技术名（如 "Vue.js"）
/// - `literal_interner`: 字面量内部存储管理器
/// - `runtime_lib`: 运行时规则库
/// - `literal_hit_ids`: 匹配到的 literal id 集合
/// - `any_hit_ids`: 匹配到的 any 类型 id 集合
/// - `contains_hit_ids`: 匹配到的 contains 类型 id 集合
#[allow(dead_code)]
#[cfg(debug_assertions)]
pub fn debug_literal_hit_matching(
    scope: Scope,
    target_tech_name: &str,
    literal_interner: &LiteralInterner,
    runtime_lib: &RuleLibraryRuntime,
    literal_hit_ids: &FxHashSet<LiteralId>,
    any_hit_ids: &FxHashSet<LiteralId>,
    contains_hit_ids: &FxHashSet<LiteralId>,
) {
    // ========== 1. LiteralHit 信息打印==========
    let literal_hit_strs: Vec<&str> = literal_hit_ids
        .iter()
        .filter_map(|&lid| literal_interner.get_literal(lid))
        .collect();
    let any_hit_strs: Vec<&str> = any_hit_ids
        .iter()
        .filter_map(|&lid| literal_interner.get_literal(lid))
        .collect();
    let contains_hit_strs: Vec<&str> = contains_hit_ids
        .iter()
        .filter_map(|&lid| literal_interner.get_literal(lid))
        .collect();

    // 基础统计日志
    debug!(
        "scope={:?} LiteralHit统计 - literal数量: {}, any数量: {}, contains数量: {}",
        scope,
        literal_hit_ids.len(),
        any_hit_ids.len(),
        contains_hit_ids.len()
    );
    debug!("scope={:?} literal_hit内容: {:?}", scope, literal_hit_strs);
    debug!("scope={:?} any_hit内容: {:?}", scope, any_hit_strs);
    debug!(
        "scope={:?} contains_hit内容: {:?}",
        scope, contains_hit_strs
    );

    // ========== 2. 精简版核心统计 ==========
    let total_hit_count = literal_hit_ids.len() + any_hit_ids.len() + contains_hit_ids.len();
    debug!(
        "[Literal调试] scope={:?} | 总匹配数: {} | literal: {} | any: {} | contains: {}",
        scope,
        total_hit_count,
        literal_hit_ids.len(),
        any_hit_ids.len(),
        contains_hit_ids.len()
    );

    // ========== 3. 指定技术名的 LiteralHit 匹配检查 ==========
    if let Some(tech) = runtime_lib
        .compiled_bundle
        .library
        .tech_patterns
        .get(target_tech_name)
    {
        let has_literal_hit = check_tech_literal_hit(
            tech,
            literal_interner,
            literal_hit_ids,
            contains_hit_ids,
        );

        // 关键调试日志
        warn!(
            "[Literal调试] scope={:?} | 技术名: {} | 是否匹配到literal: {} | 总匹配数: {}",
            scope, target_tech_name, has_literal_hit, total_hit_count
        );
    } else {
        warn!(
            "[Literal调试] scope={:?} | 技术名: {} | 规则库中未找到该技术的匹配规则",
            scope, target_tech_name
        );
    }
}

/// 辅助函数：检查指定技术是否有匹配的 LiteralHit
#[allow(dead_code)]
#[cfg(debug_assertions)]
fn check_tech_literal_hit(
    tech: &CompiledTechRule,
    literal_interner: &LiteralInterner,
    literal_hit_ids: &FxHashSet<LiteralId>,
    contains_hit_ids: &FxHashSet<LiteralId>,
) -> bool {
    // 遍历技术的 script_patterns 检查匹配
    if let Some(pats) = &tech.script_patterns {
        for pat in pats {
            // 1. 检查 require_literals 列表（字符串转ID匹配）
            if let Some(lit_str_list) = &pat.exec.match_gate.require_literals {
                for lit_str in lit_str_list {
                    if let Some(lid) = literal_interner.get_id(lit_str) {
                        if literal_hit_ids.contains(&lid) {
                            return true;
                        }
                    }
                }
            }

            // 2. 检查 require_literal_ids（直接ID匹配）
            if let Some(lit_id_list) = &pat.exec.match_gate.require_literal_ids {
                for &lid in lit_id_list {
                    if literal_hit_ids.contains(&lid) {
                        return true;
                    }
                }
            }

            // 3. 检查 contains 匹配
            if let MatcherSpec::Contains(lid) = &pat.exec.matcher {
                if contains_hit_ids.contains(lid) {
                    return true;
                }
            }
            
            // 4. 检查 require_any_literals 列表（字符串转ID匹配）
            if let Some(lit_str_list) = &pat.exec.match_gate.require_any_literals {
                for lit_str in lit_str_list {
                    if let Some(lid) = literal_interner.get_id(lit_str) {
                        if literal_hit_ids.contains(&lid) {
                            return true;
                        }
                    }
                }
            }

            // 5. 检查 require_any_literal_ids（直接ID匹配）
            if let Some(lit_id_list) = &pat.exec.match_gate.require_any_literal_ids {
                for &lid in lit_id_list {
                    if literal_hit_ids.contains(&lid) {
                        return true;
                    }
                }
            }

        }
    }

    false
}