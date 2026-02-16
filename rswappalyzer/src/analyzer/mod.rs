use log::warn;
use rswappalyzer_engine::{
    compiled::{LiteralId, LiteralInterner},
    input_evidence::{header_evidence::HeaderEvidence, html_evidence::HtmlEvidence},
    CompiledTechRule, RuleLibraryRuntime, Scope,
};
use rustc_hash::{FxHashMap, FxHashSet};

mod candidate_collector;
pub mod common;
pub mod cookie;
#[cfg(debug_assertions)]
mod debug_log;
pub mod header;
pub mod html;
pub mod meta;
pub mod script;
pub mod url;

use candidate_collector::build_all_candidate_techs;

/// 统一证据输入接口
pub trait AnalyzerInput {
    // /// 获取提取的原始TokenId集合
    // fn get_extracted_token_ids(&self) -> &FxHashSet<TokenId>;

    /// 获取contains匹配的LiteralId集合
    fn get_contains_hit_ids(&self) -> &FxHashSet<LiteralId>;

    /// 获取字面量匹配的LiteralId集合
    fn get_literal_hit_ids(&self) -> &FxHashSet<LiteralId>;

    /// 获取any匹配的LiteralId集合
    fn get_any_hit_ids(&self) -> &FxHashSet<LiteralId>;
}

/// HtmlEvidence 实现 AnalyzerInput 接口
impl<'a> AnalyzerInput for HtmlEvidence<'a> {
    // fn get_extracted_token_ids(&self) -> &FxHashSet<TokenId> {
    //     &self.html_token_ids
    // }

    fn get_contains_hit_ids(&self) -> &FxHashSet<LiteralId> {
        &self.contains_hit_ids
    }

    fn get_literal_hit_ids(&self) -> &FxHashSet<LiteralId> {
        &self.literals_hit_ids
    }

    fn get_any_hit_ids(&self) -> &FxHashSet<LiteralId> {
        &self.any_hit_ids
    }
}

/// HeaderEvidence 实现 AnalyzerInput 接口
impl<'a> AnalyzerInput for HeaderEvidence<'a> {
    // fn get_extracted_token_ids(&self) -> &FxHashSet<TokenId> {
    //     &self.header_token_ids
    // }

    fn get_contains_hit_ids(&self) -> &FxHashSet<LiteralId> {
        &self.contains_hit_ids
    }

    fn get_literal_hit_ids(&self) -> &FxHashSet<LiteralId> {
        &self.literals_hit_ids
    }

    fn get_any_hit_ids(&self) -> &FxHashSet<LiteralId> {
        &self.any_hit_ids
    }
}

/// 通用分析器骨架接口
pub trait Analyzer<P: ?Sized, D: AnalyzerInput> {
    /// 分析器类型标识（如"HTML"/"Header"/"Cookie"）
    const TYPE_NAME: &'static str;

    /// 从技术规则中提取当前维度的匹配模式
    fn get_patterns(tech: &CompiledTechRule) -> Option<&P>;

    /// 维度专属的匹配逻辑
    fn match_logic<'d>(
        tech_name: &str,
        patterns: &P,
        data: &D,
        //filtered_tokens: &FxHashSet<&str>,
        //filtered_token_ids: &FxHashSet<TokenId>,
        //token_interner: &'d TokenInterner,
        literal_interner: &'d LiteralInterner,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    );

    /// 通用分析执行流程
    #[inline(always)]
    fn analyze<'a, 'd>(
        runtime_lib: &'a RuleLibraryRuntime,
        data: &'d D,
        scope: Scope,
        detected: &mut FxHashMap<String, (u8, Option<String>)>,
    ) where
        Self: Sized,
    {
        // 获取AC扫描的LiteralId集合
        let literal_hit_ids = data.get_literal_hit_ids();
        let any_hit_ids = data.get_any_hit_ids();
        let contains_hit_ids = data.get_contains_hit_ids();

        // 提前获取所有需要的 interners
        //let token_interner = &runtime_lib.compiled_bundle.token_interner;
        let literal_interner = &runtime_lib.get_compiled_bundle().literal_interner;

        // LiteralId旁路调试
        // #[cfg(debug_assertions)]
        // if scope == Scope::Html {
        //     let debug_scope = scope;
        //     debug_log::debug_literal_hit_matching(
        //         debug_scope,
        //         "Adminer", // 要调试的技术名
        //         &literal_interner,
        //         &runtime_lib,
        //         &literal_hit_ids,
        //         &any_hit_ids,
        //         &contains_hit_ids,
        //     );
        // }

        // 若LiteralHit为空, 短路返回
        let has_literal_hits =
            !literal_hit_ids.is_empty() || !any_hit_ids.is_empty() || !contains_hit_ids.is_empty();
        if !has_literal_hits {
            return;
        }

        // 3. 构建候选技术集（使用新的Literal-based逻辑）
        let candidate_tech_ids = match build_all_candidate_techs(
            runtime_lib,
            //&filtered_token_ids,
            literal_hit_ids,
            any_hit_ids,
            contains_hit_ids,
            scope,
            //true, // 开启Literal-based候选开关
        ) {
            Ok(res) => res,
            Err(e) => {
                warn!("构建候选技术集失败: {:?}", e);
                FxHashSet::default()
            }
        };

        // 3 技术名称转换
        // 转换TechId为String名称
        let tech_interner = &runtime_lib.get_compiled_bundle().tech_interner;
        let candidate_tech_names: FxHashSet<&str> = candidate_tech_ids
            .iter()
            .filter_map(|&tech_id| tech_interner.get_name(tech_id))
            .collect();

        // 4 执行匹配逻辑
        // 遍历候选技术执行匹配
        for tech_name in candidate_tech_names {
            let Some(tech) = runtime_lib
                .get_compiled_lib()
                .tech_patterns
                .get(tech_name)
            else {
                continue;
            };
            let Some(patterns) = Self::get_patterns(tech) else {
                continue;
            };

            Self::match_logic(
                tech_name,
                patterns,
                data,
                //&filtered_tokens,
                //&filtered_token_ids,
                //token_interner,
                literal_interner,
                detected,
            );
        }
    }
}
