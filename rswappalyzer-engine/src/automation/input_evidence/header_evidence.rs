use crate::{
    ac_scanner::AcScanner,
    automation::cache::AcAutomatonCache,
    compiled::{CompiledBundle, LiteralId},
};
use rustc_hash::{FxHashMap, FxHashSet};

/// 标准化Cookie结构体
#[derive(Debug, Clone)]
pub struct StandardCookie {
    pub name: String,
    pub value: String,
    pub source: String,
}

/// Header/Cookie维度证据快照：存储Header/Cookie的扫描结果
#[derive(Debug)]
pub struct HeaderEvidence<'a> {
    /// 原始Header键值对引用
    pub header_map: &'a FxHashMap<String, String>,
    /// 标准化Cookie列表引用
    pub cookies: &'a [StandardCookie],

    // 原始未转换的匹配结果（存储ID）
    /// 剪枝层 - Literal类型匹配结果（原始LiteralId）
    pub literals_hit_ids: FxHashSet<LiteralId>,
    /// 剪枝层 - Any类型匹配结果（原始LiteralId）
    pub any_hit_ids: FxHashSet<LiteralId>,
    /// 匹配层 - Contains类型匹配结果（原始LiteralId）
    pub contains_hit_ids: FxHashSet<LiteralId>,
}

impl<'a> HeaderEvidence<'a> {
    /// 适配ID化的构建方法（核心优化：存储ID而非字符串）
    #[inline(always)]
    pub fn build(
        header_map: &'a FxHashMap<String, String>,
        cookies: &'a [StandardCookie],
        ac_cache: &AcAutomatonCache, // 替换str_to_all_kinds
        bundle: &CompiledBundle,     // ID转字符串（按需使用）
        //header_token_ids: FxHashSet<TokenId>,
    ) -> Self {
        // 初始化ID集合
        let mut literals_hit_ids = FxHashSet::default();
        let mut any_hit_ids = FxHashSet::default();
        let mut contains_hit_ids = FxHashSet::default();

        // 扫描Header（is_html=false表示Header维度，传入ID集合）
        for (key, val) in header_map {
            AcScanner::scan_and_classify_with_id(
                key,
                &ac_cache.header_combined_ac,
                ac_cache,
                false, // 区分Header维度
                &mut literals_hit_ids,
                &mut any_hit_ids,
                &mut contains_hit_ids,
                bundle,
            );
            AcScanner::scan_and_classify_with_id(
                val,
                &ac_cache.header_combined_ac,
                ac_cache,
                false,
                &mut literals_hit_ids,
                &mut any_hit_ids,
                &mut contains_hit_ids,
                bundle,
            );
        }

        // 扫描Cookie
        for cookie in cookies {
            AcScanner::scan_and_classify_with_id(
                &cookie.name,
                &ac_cache.header_combined_ac,
                ac_cache,
                false,
                &mut literals_hit_ids,
                &mut any_hit_ids,
                &mut contains_hit_ids,
                bundle,
            );
            AcScanner::scan_and_classify_with_id(
                &cookie.value,
                &ac_cache.header_combined_ac,
                ac_cache,
                false,
                &mut literals_hit_ids,
                &mut any_hit_ids,
                &mut contains_hit_ids,
                bundle,
            );
        }

        Self {
            header_map,
            cookies,
            literals_hit_ids,
            any_hit_ids,
            contains_hit_ids,
        }
    }
}
